// use async_trait::async_trait;
use crate::db::{Cache, Db};
use crate::idprovider::interface::{
    AuthCredHandler,
    AuthResult,
    GroupToken,
    GroupTokenState,
    Id,
    IdProvider,
    IdpError,
    ProviderOrigin,
    // KeyStore,
    UserToken,
    UserTokenState,
};
use crate::idprovider::system::{
    Shadow, SystemAuthResult, SystemProvider, SystemProviderAuthInit, SystemProviderSession,
};
use hashbrown::HashMap;
use kanidm_hsm_crypto::provider::BoxedDynTpm;
use kanidm_unix_common::constants::{
    DEFAULT_CACHE_TIMEOUT_JITTER_MS, DEFAULT_CACHE_TIMEOUT_MAXIMUM, DEFAULT_CACHE_TIMEOUT_MINIMUM,
    DEFAULT_SHELL_SEARCH_PATHS, SYSTEM_SHADOW_PATH,
};
use kanidm_unix_common::unix_config::{HomeAttr, UidAttr};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcShadow, EtcUser};
use kanidm_unix_common::unix_proto::{
    HomeDirectoryInfo, NssGroup, NssUser, PamAuthRequest, PamAuthResponse, PamServiceInfo,
    ProviderStatus,
};
use lru::LruCache;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use uuid::Uuid;

const NXCACHE_SIZE: NonZeroUsize =
    NonZeroUsize::new(256).expect("Invalid NXCACHE constant at compile time");
// Can sometimes have duplicates, so it can be a bit longer.
const ASYNC_REFRESH_QUEUE: usize = 128;

pub enum AuthSession {
    Online {
        client: Arc<dyn IdProvider + Sync + Send>,
        account_id: String,
        id: Id,
        cred_handler: AuthCredHandler,
        /// Some authentication operations may need to spawn background tasks. These tasks need
        /// to know when to stop as the caller has disconnected. This receiver allows that, so
        /// that tasks which .resubscribe() to this channel can then select! on it and be notified
        /// when they need to stop.
        shutdown_rx: broadcast::Receiver<()>,
    },
    Offline {
        account_id: String,
        id: Id,
        client: Arc<dyn IdProvider + Sync + Send>,
        session_token: Box<UserToken>,
        cred_handler: AuthCredHandler,
    },
    System {
        account_id: String,
        id: Id,
        cred_handler: AuthCredHandler,
        shadow: Arc<Shadow>,
    },
    Success,
    Denied,
}

impl AuthSession {
    pub fn is_complete(&self) -> bool {
        match &self {
            Self::Success | Self::Denied => true,
            Self::Online { .. } | Self::Offline { .. } | Self::System { .. } => false,
        }
    }
}

#[derive(Debug, PartialEq)]
/// The expiration state of a cache item
enum ExpiryState {
    /// The item is valid
    Valid,
    /// The item is valid, but approaching it's expiry so a background/async refresh should be
    /// performed.
    ValidRefresh,
    /// The item is expired and needs refresh before we can proceed
    Expired,
}

pub struct Resolver {
    // Generic / modular types.
    db: Db,
    hsm: Mutex<BoxedDynTpm>,

    // A local passwd/shadow resolver.
    system_provider: Arc<SystemProvider>,

    // client: Box<dyn IdProvider + Sync + Send>,
    client_ids: HashMap<ProviderOrigin, Arc<dyn IdProvider + Sync + Send>>,

    // A set of remote resolvers, ordered by priority.
    clients: Vec<Arc<dyn IdProvider + Sync + Send>>,

    // The id of the primary-provider which may use name over spn.
    primary_origin: ProviderOrigin,

    timeout_seconds: u64,
    async_refresh_seconds: u64,
    default_shell: String,
    home_prefix: PathBuf,
    home_attr: HomeAttr,
    home_alias: Option<HomeAttr>,
    uid_attr_map: UidAttr,
    gid_attr_map: UidAttr,
    nxcache: Mutex<LruCache<Id, SystemTime>>,
    async_refresh_tx: mpsc::Sender<Id>,
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            Id::Name(s) => s.to_string(),
            Id::Gid(g) => g.to_string(),
        })
    }
}

impl Resolver {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        db: Db,
        system_provider: Arc<SystemProvider>,
        clients: Vec<Arc<dyn IdProvider + Sync + Send>>,
        hsm: BoxedDynTpm,
        timeout_seconds: u64,
        default_shell: String,
        home_prefix: PathBuf,
        home_attr: HomeAttr,
        home_alias: Option<HomeAttr>,
        uid_attr_map: UidAttr,
        gid_attr_map: UidAttr,
    ) -> Result<(Self, mpsc::Receiver<Id>), ()> {
        let hsm = Mutex::new(hsm);

        let primary_origin = clients.first().map(|c| c.origin()).unwrap_or_default();

        let client_ids: HashMap<_, _> = clients
            .iter()
            .map(|provider| (provider.origin(), provider.clone()))
            .collect();

        let (async_refresh_tx, async_refresh_rx) = mpsc::channel(ASYNC_REFRESH_QUEUE);

        // How many seconds before expiry should we be refreshing an entry.
        // We want to balance this - we don't want too many refreshes, but we
        // also need to account for long cache times and ensuring that we are checking
        // account validity in the background.

        let timeout_seconds =
            timeout_seconds.clamp(DEFAULT_CACHE_TIMEOUT_MINIMUM, DEFAULT_CACHE_TIMEOUT_MAXIMUM);
        let async_refresh_seconds = (timeout_seconds / 3) * 2;

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok((
            Resolver {
                db,
                hsm,
                system_provider,
                clients,
                primary_origin,
                client_ids,
                timeout_seconds,
                async_refresh_seconds,
                default_shell,
                home_prefix,
                home_attr,
                home_alias,
                uid_attr_map,
                gid_attr_map,
                nxcache: Mutex::new(LruCache::new(NXCACHE_SIZE)),
                async_refresh_tx,
            },
            async_refresh_rx,
        ))
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn mark_next_check_now(&self, now: SystemTime) {
        for c in self.clients.iter() {
            c.mark_next_check(now).await;
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn mark_offline(&self) {
        for c in self.clients.iter() {
            c.mark_offline().await;
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn clear_cache(&self) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        dbtxn.clear().and_then(|_| dbtxn.commit()).map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn invalidate(&self) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        dbtxn
            .invalidate()
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_cached_usertokens(&self) -> Result<Vec<UserToken>, ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_accounts().map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_cached_grouptokens(&self) -> Result<Vec<GroupToken>, ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_groups().map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn set_nxcache(&self, id: &Id) {
        let mut nxcache_txn = self.nxcache.lock().await;
        // To try and prevent too many requests occuring all at the same time, we subtract a small
        // amount of "jitter" from expiry values so that we space out refreshes.
        let jitter = rand::random_range(0..DEFAULT_CACHE_TIMEOUT_JITTER_MS);
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds)
            - Duration::from_millis(jitter);
        nxcache_txn.put(id.clone(), ex_time);
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn check_nxcache(&self, id: &Id) -> Option<SystemTime> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.get(id).copied()
    }

    #[instrument(level = "info", skip_all)]
    pub async fn reload_system_identities(
        &self,
        users: Vec<EtcUser>,
        shadow: Vec<EtcShadow>,
        groups: Vec<EtcGroup>,
    ) {
        self.system_provider.reload(users, shadow, groups).await
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_cached_usertoken(
        &self,
        account_id: &Id,
        current_time: SystemTime,
    ) -> Result<(ExpiryState, Option<UserToken>), ()> {
        // Is it in the nxcache?
        if let Some(ex_time) = self.check_nxcache(account_id).await {
            if current_time >= ex_time {
                // It's in the LRU, but we are past the expiry so
                // lets attempt a refresh.
                return Ok((ExpiryState::ValidRefresh, None));
            } else {
                // It's in the LRU and still valid, so return that
                // no check is needed.
                return Ok((ExpiryState::Valid, None));
            }
        }

        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let r = dbtxn.get_account(account_id).map_err(|err| {
            debug!(?err, "get_cached_usertoken");
        })?;

        drop(dbtxn);

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let ex_time = SystemTime::UNIX_EPOCH + Duration::from_secs(ex);

                // Should we async refresh?
                let async_ref_time = if ex > self.async_refresh_seconds {
                    SystemTime::UNIX_EPOCH + Duration::from_secs(ex - self.async_refresh_seconds)
                } else {
                    ex_time
                };

                if current_time >= ex_time {
                    Ok((ExpiryState::Expired, Some(ut)))
                } else if current_time >= async_ref_time {
                    Ok((ExpiryState::ValidRefresh, Some(ut)))
                } else {
                    Ok((ExpiryState::Valid, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB, and it wasn't in the nxcache.
                Ok((ExpiryState::Expired, None))
            }
        } // end match r
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_cached_grouptoken(&self, grp_id: &Id) -> Result<(bool, Option<GroupToken>), ()> {
        let current_time = SystemTime::now();
        // Is it in the nxcache?
        if let Some(ex_time) = self.check_nxcache(grp_id).await {
            if current_time >= ex_time {
                // It's in the LRU, but we are past the expiry so
                // lets attempt a refresh.
                return Ok((true, None));
            } else {
                // It's in the LRU and still valid, so return that
                // no check is needed.
                return Ok((false, None));
            }
        }
        // grp_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let r = dbtxn.get_group(grp_id).map_err(|err| {
            debug!(?err, "get_cached_grouptoken");
        })?;

        drop(dbtxn);

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;

                if current_time >= ex_time {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB, and it wasn't in the nxcache.
                Ok((true, None))
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn set_cache_usertoken(
        &self,
        token: &mut UserToken,
        // This is just for proof that only one write can occur at a time.
        _tpm: &mut BoxedDynTpm,
    ) -> Result<(), ()> {
        // Set an expiry
        // To try and prevent too many requests occuring all at the same time, we subtract a small
        // amount of "jitter" from expiry values so that we space out refreshes.
        let jitter = rand::random_range(0..DEFAULT_CACHE_TIMEOUT_JITTER_MS);
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds)
            - Duration::from_millis(jitter);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!(
                    "Time conversion error - cache expiry time became less than epoch? {:?}",
                    e
                );
            })?;

        // Check if requested `shell` exists on the system, else use `default_shell`
        let maybe_shell = token.shell.as_ref().map(PathBuf::from);

        let requested_shell_exists = if let Some(shell_path) = maybe_shell.as_ref() {
            // Does the shell path as configured exist?
            let mut exists = shell_path
                .canonicalize()
                .map_err(|err| {
                    debug!(
                        "Failed to canonicalize path, using base path. Tried: {} Error: {:?}",
                        shell_path.to_string_lossy(),
                        err
                    );
                })
                .unwrap_or(Path::new(shell_path).to_path_buf())
                .exists();

            if !exists {
                // Does the shell binary exist in a search path that is configured?
                if let Some(shell_binary_name) = shell_path.file_name() {
                    for search_path in DEFAULT_SHELL_SEARCH_PATHS {
                        //
                        let shell_path = Path::new(search_path).join(shell_binary_name);
                        if shell_path.exists() {
                            // Okay, the binary name exists but in an alternate path. This can
                            // commonly occur with freebsd where the shell may be installed
                            // in /usr/local/bin instead of /bin.
                            //
                            // This could also occur if the user configured the shell as "zsh"
                            // rather than an absolute path.
                            let Some(shell_path_utf8) = shell_path.to_str().map(String::from)
                            else {
                                warn!("Configured shell \"{}\" for {} was found but the complete path is not valid utf-8 and can not be used.",
                                        shell_binary_name.to_string_lossy(), token.name);
                                continue;
                            };

                            // Update the path
                            token.shell = Some(shell_path_utf8);
                            // We exist
                            exists = true;
                            // No need to loop any more
                            break;
                        }
                    }
                }
            }

            if !exists {
                warn!(
                        "Configured shell \"{}\" for {} is not present on this system. Check `/etc/shells` for valid shell options.",
                        shell_path.to_string_lossy(), token.name
                    )
            }

            exists
        } else {
            info!("User has not specified a shell, using default");
            false
        };

        if !requested_shell_exists {
            token.shell = Some(self.default_shell.clone())
        }

        let mut dbtxn = self.db.write().await;
        token
            .groups
            .iter()
            // We need to add the groups first
            .try_for_each(|g| dbtxn.update_group(g, offset.as_secs()))
            .and_then(|_|
                // So that when we add the account it can make the relationships.
                dbtxn
                    .update_account(token, offset.as_secs()))
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn set_cache_grouptoken(&self, token: &GroupToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        let mut dbtxn = self.db.write().await;
        dbtxn
            .update_group(token, offset.as_secs())
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn delete_cache_usertoken(&self, a_uuid: Uuid) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_account(a_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    async fn delete_cache_grouptoken(&self, g_uuid: Uuid) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_group(g_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn refresh_usertoken(
        &self,
        account_id: &Id,
        current_time: SystemTime,
    ) -> Result<Option<UserToken>, ()> {
        let mut hsm_lock = self.hsm.lock().await;

        // We need to re-acquire the token now behind the hsmlock - this is so that
        // we know that as we write the updated token, we know that no one else has
        // written to this token, since we are now the only task that is allowed
        // to be in a write phase.
        let token = self
            .get_cached_usertoken(account_id, current_time)
            .await
            .map(|(_expired, option_token)| option_token)
            .map_err(|err| {
                debug!(?err, "get_usertoken error");
            })?;

        let user_get_result = if let Some(tok) = token.as_ref() {
            // Re-use the provider that the token is from.
            match self.client_ids.get(&tok.provider) {
                Some(client) => {
                    client
                        .unix_user_get(
                            account_id,
                            token.as_ref(),
                            hsm_lock.deref_mut(),
                            current_time,
                        )
                        .await
                }
                None => {
                    error!(provider = ?tok.provider, "Token was resolved by a provider that no longer appears to be present.");

                    // We don't want to use a token from a former provider, we want it refreshed,
                    // so lets indicate that we didn't find the token. If we return useCcahed like
                    // we did previously, we'd never clear and reset this token since we'd never
                    // locate it's provider.
                    Ok(UserTokenState::NotFound)
                }
            }
        } else {
            // We've never seen it before, so iterate over the providers in priority order.
            'search: {
                for client in self.clients.iter() {
                    match client
                        .unix_user_get(
                            account_id,
                            token.as_ref(),
                            hsm_lock.deref_mut(),
                            current_time,
                        )
                        .await
                    {
                        // Ignore this one.
                        Ok(UserTokenState::NotFound) => {}
                        result => break 'search result,
                    }
                }
                break 'search Ok(UserTokenState::NotFound);
            }
        };

        match user_get_result {
            Ok(UserTokenState::Update(mut n_tok)) => {
                // We have the token!
                self.set_cache_usertoken(&mut n_tok, hsm_lock.deref_mut())
                    .await?;
                Ok(Some(n_tok))
            }
            Ok(UserTokenState::NotFound) => {
                // It previously existed, so now purge it.
                if let Some(tok) = token {
                    self.delete_cache_usertoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(account_id).await;
                Ok(None)
            }
            Ok(UserTokenState::UseCached) => Ok(token),
            Err(err) => {
                // Something went wrong, we don't know what, but lets return the token
                // anyway.
                error!(?err);
                Ok(token)
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn refresh_grouptoken(
        &self,
        grp_id: &Id,
        token: Option<GroupToken>,
        current_time: SystemTime,
    ) -> Result<Option<GroupToken>, ()> {
        let mut hsm_lock = self.hsm.lock().await;

        let group_get_result = if let Some(tok) = token.as_ref() {
            // Re-use the provider that the token is from.
            match self.client_ids.get(&tok.provider) {
                Some(client) => {
                    client
                        .unix_group_get(grp_id, hsm_lock.deref_mut(), current_time)
                        .await
                }
                None => {
                    error!(provider = ?tok.provider, "Token was resolved by a provider that no longer appears to be present.");
                    // We don't want to use a token from a former provider, we want it refreshed,
                    // so lets indicate that we didn't find the token. If we return useCcahed like
                    // we did previously, we'd never clear and reset this token since we'd never
                    // locate it's provider.
                    Ok(GroupTokenState::NotFound)
                }
            }
        } else {
            // We've never seen it before, so iterate over the providers in priority order.
            'search: {
                for client in self.clients.iter() {
                    match client
                        .unix_group_get(grp_id, hsm_lock.deref_mut(), current_time)
                        .await
                    {
                        // Ignore this one.
                        Ok(GroupTokenState::NotFound) => {}
                        result => break 'search result,
                    }
                }
                break 'search Ok(GroupTokenState::NotFound);
            }
        };

        drop(hsm_lock);

        match group_get_result {
            Ok(GroupTokenState::Update(n_tok)) => {
                self.set_cache_grouptoken(&n_tok).await?;
                Ok(Some(n_tok))
            }
            Ok(GroupTokenState::NotFound) => {
                if let Some(tok) = token {
                    self.delete_cache_grouptoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(grp_id).await;
                Ok(None)
            }
            Ok(GroupTokenState::UseCached) => Ok(token),
            Err(err) => {
                // Some other transient error, continue with the token.
                error!(?err);
                Ok(token)
            }
        }
    }

    #[instrument(level = "trace", skip_all)]
    async fn get_usertoken(
        &self,
        account_id: &Id,
        current_time: SystemTime,
    ) -> Result<Option<UserToken>, ()> {
        // get the item from the cache
        let (expiry_state, item) = self
            .get_cached_usertoken(account_id, current_time)
            .await
            .map_err(|e| {
                debug!("get_usertoken error -> {:?}", e);
            })?;

        // If the token isn't found, get_cached will set expired = true.
        if expiry_state == ExpiryState::Expired {
            self.refresh_usertoken(account_id, current_time).await
        } else {
            if expiry_state == ExpiryState::ValidRefresh {
                // We don't mind if the buffer is full.
                if self.async_refresh_tx.try_send(account_id.clone()).is_err() {
                    debug!(?account_id, "unable to queue async refresh");
                }
            }
            // Still valid, return the cached entry.
            Ok(item)
        }
        .map(|t| {
            trace!("token -> {:?}", t);
            t
        })
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_grouptoken(
        &self,
        grp_id: Id,
        current_time: SystemTime,
    ) -> Result<Option<GroupToken>, ()> {
        let (expired, item) = self.get_cached_grouptoken(&grp_id).await.map_err(|e| {
            debug!("get_grouptoken error -> {:?}", e);
        })?;

        if expired {
            self.refresh_grouptoken(&grp_id, item, current_time).await
        } else {
            // Still valid, return the cached entry.
            Ok(item)
        }
        .map(|t| {
            trace!("token -> {:?}", t);
            t
        })
    }

    async fn get_groupmembers(&self, g_uuid: Uuid) -> Vec<String> {
        let mut dbtxn = self.db.write().await;

        dbtxn
            .get_group_members(g_uuid)
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .map(|ut| self.token_uidattr(&ut))
            .collect()
    }

    // Get ssh keys for an account id
    #[instrument(level = "debug", skip(self))]
    pub async fn get_sshkeys(&self, account_id: &str) -> Result<Vec<String>, ()> {
        let current_time = SystemTime::now();
        let token = self
            .get_usertoken(&Id::Name(account_id.to_string()), current_time)
            .await?;
        Ok(token
            .map(|t| {
                // Only return keys if the account is valid
                if t.valid {
                    t.sshkeys
                } else {
                    Vec::with_capacity(0)
                }
            })
            .unwrap_or_else(|| Vec::with_capacity(0)))
    }

    fn token_homedirectory_alias(&self, token: &UserToken) -> Option<String> {
        let is_primary_origin = token.provider == self.primary_origin;
        self.home_alias.map(|t| match t {
            // If we have an alias. use it.
            HomeAttr::Name if is_primary_origin => token.name.as_str().to_string(),
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn | HomeAttr::Name => token.spn.as_str().to_string(),
        })
    }

    fn token_homedirectory_attr(&self, token: &UserToken) -> String {
        let is_primary_origin = token.provider == self.primary_origin;
        match self.home_attr {
            HomeAttr::Name if is_primary_origin => token.name.as_str().to_string(),
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn | HomeAttr::Name => token.spn.as_str().to_string(),
        }
    }

    fn token_homedirectory(&self, token: &UserToken) -> String {
        self.token_homedirectory_alias(token)
            .unwrap_or_else(|| self.token_homedirectory_attr(token))
    }

    fn token_abs_homedirectory(&self, token: &UserToken) -> String {
        self.home_prefix
            .join(self.token_homedirectory(token))
            .to_string_lossy()
            .to_string()
    }

    fn token_uidattr(&self, token: &UserToken) -> String {
        let is_primary_origin = token.provider == self.primary_origin;
        match self.uid_attr_map {
            UidAttr::Name if is_primary_origin => token.name.as_str(),
            UidAttr::Spn | UidAttr::Name => token.spn.as_str(),
        }
        .to_string()
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn get_nssaccounts(&self) -> Result<Vec<NssUser>, ()> {
        // We don't need to filter the cached tokens as the cache shouldn't
        // have anything that collides with system.
        let system_nss_users = self.system_provider.get_nssaccounts().await;

        let cached = self.get_cached_usertokens().await?;

        Ok(system_nss_users
            .into_iter()
            .chain(cached.into_iter().map(|tok| NssUser {
                homedir: self.token_abs_homedirectory(&tok),
                name: self.token_uidattr(&tok),
                uid: tok.gidnumber,
                gid: tok.gidnumber,
                gecos: tok.displayname,
                shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
            }))
            .collect())
    }

    #[instrument(level = "trace", skip_all)]
    async fn get_nssaccount(
        &self,
        account_id: Id,
        current_time: SystemTime,
    ) -> Result<Option<NssUser>, ()> {
        if let Some(nss_user) = self.system_provider.get_nssaccount(&account_id).await {
            debug!("system provider satisfied request");
            return Ok(Some(nss_user));
        }

        let token = self.get_usertoken(&account_id, current_time).await?;
        Ok(token.map(|tok| NssUser {
            homedir: self.token_abs_homedirectory(&tok),
            name: self.token_uidattr(&tok),
            uid: tok.gidnumber,
            gid: tok.gidnumber,
            gecos: tok.displayname,
            shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
        }))
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssaccount_name_time(
        &self,
        account_id: &str,
        current_time: SystemTime,
    ) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Name(account_id.to_string()), current_time)
            .await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssaccount_name(&self, account_id: &str) -> Result<Option<NssUser>, ()> {
        let current_time = SystemTime::now();
        self.get_nssaccount(Id::Name(account_id.to_string()), current_time)
            .await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssaccount_gid(&self, gid: u32) -> Result<Option<NssUser>, ()> {
        let current_time = SystemTime::now();
        self.get_nssaccount(Id::Gid(gid), current_time).await
    }

    fn token_gidattr(&self, token: &GroupToken) -> String {
        match self.gid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn get_nssgroups(&self) -> Result<Vec<NssGroup>, ()> {
        let mut r = self.system_provider.get_nssgroups().await;

        // Extend all the local groups if maps exist.
        for nss_group in r.iter_mut() {
            for client in self.clients.iter() {
                if let Some(extend_group_id) = client.has_map_group(&nss_group.name) {
                    let (_, token) = self.get_cached_grouptoken(extend_group_id).await?;
                    if let Some(token) = token {
                        let members = self.get_groupmembers(token.uuid).await;
                        nss_group.members.extend(members);
                        debug!(
                            "extended group {} with members from {}",
                            nss_group.name, token.name
                        );
                    }
                }
            }
        }

        let l = self.get_cached_grouptokens().await?;
        r.reserve(l.len());
        for tok in l.into_iter() {
            let members = self.get_groupmembers(tok.uuid).await;
            r.push(NssGroup {
                name: self.token_gidattr(&tok),
                gid: tok.gidnumber,
                members,
            })
        }
        Ok(r)
    }

    #[instrument(level = "trace", skip_all)]
    async fn get_nssgroup(&self, grp_id: Id) -> Result<Option<NssGroup>, ()> {
        if let Some(mut nss_group) = self.system_provider.get_nssgroup(&grp_id).await {
            debug!("system provider satisfied request");

            for client in self.clients.iter() {
                if let Some(extend_group_id) = client.has_map_group(&nss_group.name) {
                    let token = self
                        .get_grouptoken(extend_group_id.clone(), SystemTime::now())
                        .await?;
                    if let Some(token) = token {
                        let members = self.get_groupmembers(token.uuid).await;
                        nss_group.members.extend(members);
                        debug!(
                            "extended group {} with members from {}",
                            nss_group.name, token.name
                        );
                    }
                }
            }

            nss_group.members.sort_unstable();
            nss_group.members.dedup();

            return Ok(Some(nss_group));
        }

        let token = self.get_grouptoken(grp_id, SystemTime::now()).await?;
        // Get members set.
        match token {
            Some(tok) => {
                let members = self.get_groupmembers(tok.uuid).await;
                Ok(Some(NssGroup {
                    name: self.token_gidattr(&tok),
                    gid: tok.gidnumber,
                    members,
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssgroup_name(&self, grp_id: &str) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Name(grp_id.to_string())).await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssgroup_gid(&self, gid: u32) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Gid(gid)).await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn pam_account_allowed(&self, account_id: &str) -> Result<Option<bool>, ()> {
        let current_time = SystemTime::now();
        let id = Id::Name(account_id.to_string());

        if let Some(answer) = self.system_provider.authorise(&id).await {
            return Ok(Some(answer));
        };

        // Not a system account, handle with the provider.
        let token = self.get_usertoken(&id, current_time).await?;

        // If there is no token, return Ok(None) to trigger unknown-user path in pam.
        match token {
            Some(token) => {
                let client = self.client_ids.get(&token.provider)
                    .cloned()
                    .ok_or_else(|| {
                        error!(provider = ?token.provider, "Token was resolved by a provider that no longer appears to be present.");
                    })?;

                client.unix_user_authorise(&token).await.map_err(|err| {
                    error!(?err, "unable to authorise account");
                })
            }
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip(self, shutdown_rx, current_time))]
    pub async fn pam_account_authenticate_init(
        &self,
        account_id: &str,
        pam_info: &PamServiceInfo,
        current_time: OffsetDateTime,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(AuthSession, PamAuthResponse), ()> {
        // Setup an auth session. If possible bring the resolver online.
        // Further steps won't attempt to bring the cache online to prevent
        // weird interactions - they should assume online/offline only for
        // the duration of their operation. A failure of connectivity during
        // an online operation will take the cache offline however.
        let now = SystemTime::now();

        let id = Id::Name(account_id.to_string());

        match self.system_provider.auth_init(&id, current_time).await {
            // The system provider will not take part in this authentication.
            SystemProviderAuthInit::Ignore => {
                debug!(?account_id, "account unknown to system provider, continue.");
            }
            // The provider knows the account, and is unable to proceed,
            // We return unknown here so that pam_kanidm can be skipped and fall back
            // to pam_unix.so.
            SystemProviderAuthInit::ShadowMissing => {
                warn!(
                    ?account_id,
                    "Resolver unable to proceed, {SYSTEM_SHADOW_PATH} was not accessible."
                );
                return Ok((AuthSession::Denied, PamAuthResponse::Unknown));
            }
            // There are no credentials for this account
            SystemProviderAuthInit::CredentialsUnavailable => {
                warn!(
                    ?account_id,
                    "Denying auth request for system user with no valid credentials"
                );
                return Ok((AuthSession::Denied, PamAuthResponse::Denied));
            }
            // The account has expired
            SystemProviderAuthInit::Expired => {
                warn!(
                    ?account_id,
                    "Denying auth request for system user with expired credentials"
                );
                return Ok((AuthSession::Denied, PamAuthResponse::Denied));
            }
            // The provider knows the account and wants to proceed,
            SystemProviderAuthInit::Begin {
                next_request,
                cred_handler,
                shadow,
            } => {
                let auth_session = AuthSession::System {
                    account_id: account_id.to_string(),
                    id,
                    shadow,
                    cred_handler,
                };

                return Ok((auth_session, next_request.into()));
            }
        }

        let token = self.get_usertoken(&id, now).await?;

        // Get the provider associated to this token.

        let mut hsm_lock = self.hsm.lock().await;

        // We don't care if we are expired - we will always attempt to go
        // online and perform this operation online if possible.

        if let Some(token) = token {
            // We have a token, we know what provider is needed
            let client = self.client_ids.get(&token.provider)
                .cloned()
                .ok_or_else(|| {
                    error!(provider = ?token.provider, "Token was resolved by a provider that no longer appears to be present.");
                })?;

            // Can the auth proceed offline? This is important for us to make choices about
            // if we attempt to force an online state check.
            let can_proceed_offline = client.unix_user_can_offline_auth(&token).await;

            // We can use is_online here because the earlier get_usertoken call leading up to this
            // will have taken the provider online if possible. This way if we are already in an
            // offline state, we don't needlessly delay the authentication operation.
            // In addition as we now have background prefetching of accounts, this will also
            // be checking frequently enough if we are online and will assist us to be online as
            // much as possible.
            let online_at_init = if can_proceed_offline {
                // This is only for accounts we have previously resolved and authenticated.
                client.is_online().await
            } else {
                // We know who the user is, but don't have cached credentials, so we need to try and
                // force online if possible.
                client.attempt_online(hsm_lock.deref_mut(), now).await
            };

            // We're online, go for it.
            if online_at_init {
                let init_result = client
                    .unix_user_online_auth_init(
                        account_id,
                        &token,
                        hsm_lock.deref_mut(),
                        &shutdown_rx,
                    )
                    .await;

                match init_result {
                    Ok((next_req, cred_handler)) => {
                        let auth_session = AuthSession::Online {
                            client,
                            account_id: account_id.to_string(),
                            id,
                            cred_handler,
                            shutdown_rx,
                        };
                        Ok((auth_session, next_req.into()))
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        Err(())
                    }
                }
            } else {
                let init_result = client.unix_user_offline_auth_init(&token).await;
                match init_result {
                    Ok((next_req, cred_handler)) => {
                        let auth_session = AuthSession::Offline {
                            account_id: account_id.to_string(),
                            id,
                            client,
                            session_token: Box::new(token),
                            cred_handler,
                        };
                        Ok((auth_session, next_req.into()))
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        Err(())
                    }
                }
            }
        } else {
            // We don't know anything about this user. Can we try to auth them?

            // TODO: If any provider is offline should we fail the auth? I can imagine a possible
            // issue where if we had provides A, B, C stacked, and A was offline, then B could
            // service an auth that A *should* have serviced.

            for client in self.clients.iter() {
                let online_at_init = client.attempt_online(hsm_lock.deref_mut(), now).await;
                debug!(?online_at_init);

                if !online_at_init {
                    warn!(?account_id, "Unable to proceed with authentication, all providers must be online for unknown user authentication.");
                    return Ok((AuthSession::Denied, PamAuthResponse::Unknown));
                }
            }

            for client in self.clients.iter() {
                let init_result = client
                    .unix_unknown_user_online_auth_init(
                        account_id,
                        hsm_lock.deref_mut(),
                        &shutdown_rx,
                    )
                    .await;

                match init_result {
                    Ok(Some((next_req, cred_handler))) => {
                        let auth_session = AuthSession::Online {
                            client: client.clone(),
                            account_id: account_id.to_string(),
                            id,
                            cred_handler,
                            shutdown_rx,
                        };
                        return Ok((auth_session, next_req.into()));
                    }
                    Ok(None) => {
                        // Not for us, check the next provider.
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        return Err(());
                    }
                }
            }

            // No module signaled that they want it, bail.
            warn!("No provider is willing to service authentication of unknown account.");
            Ok((AuthSession::Denied, PamAuthResponse::Unknown))
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn pam_account_authenticate_step(
        &self,
        auth_session: &mut AuthSession,
        pam_next_req: PamAuthRequest,
    ) -> Result<PamAuthResponse, ()> {
        let current_time = SystemTime::now();
        let mut hsm_lock = self.hsm.lock().await;

        let maybe_err = match &mut *auth_session {
            &mut AuthSession::Online {
                ref client,
                ref account_id,
                ref id,
                ref mut cred_handler,
                ref shutdown_rx,
            } => {
                // This is not used in the authentication, but is so that any new
                // extra keys or data on the token are updated correctly if the authentication
                // requests an update. Since we hold the hsm_lock, no other task can
                // update this token between now and completion of the fn.
                let current_token = self
                    .get_cached_usertoken(id, current_time)
                    .await
                    .map(|(_expired, option_token)| option_token)
                    .map_err(|err| {
                        debug!(?err, "get_usertoken error");
                    })?;

                let result = client
                    .unix_user_online_auth_step(
                        account_id,
                        current_token.as_ref(),
                        cred_handler,
                        pam_next_req,
                        hsm_lock.deref_mut(),
                        shutdown_rx,
                    )
                    .await;

                match result {
                    Ok(AuthResult::SuccessUpdate { .. } | AuthResult::Success) => {
                        info!(?account_id, "Authentication Success");
                    }
                    Ok(AuthResult::Denied) => {
                        info!(?account_id, "Authentication Denied");
                    }
                    Ok(AuthResult::Next(_)) => {
                        info!(?account_id, "Authentication Continue");
                    }
                    _ => {}
                };

                result
            }
            &mut AuthSession::Offline {
                ref account_id,
                ref id,
                ref client,
                ref session_token,
                ref mut cred_handler,
            } => {
                // This is not used in the authentication, but is so that any new
                // extra keys or data on the token are updated correctly if the authentication
                // requests an update. Since we hold the hsm_lock, no other task can
                // update this token between now and completion of the fn.
                let current_token = self
                    .get_cached_usertoken(id, current_time)
                    .await
                    .map(|(_expired, option_token)| option_token)
                    .map_err(|err| {
                        debug!(?err, "get_usertoken error");
                    })?;

                // We are offline, continue. Remember, authsession should have
                // *everything you need* to proceed here!
                let result = client
                    .unix_user_offline_auth_step(
                        current_token.as_ref(),
                        session_token,
                        cred_handler,
                        pam_next_req,
                        hsm_lock.deref_mut(),
                    )
                    .await;

                match result {
                    Ok(AuthResult::SuccessUpdate { .. } | AuthResult::Success) => {
                        info!(?account_id, "Authentication Success");
                    }
                    Ok(AuthResult::Denied) => {
                        info!(?account_id, "Authentication Denied");
                    }
                    Ok(AuthResult::Next(_)) => {
                        info!(?account_id, "Authentication Continue");
                    }
                    _ => {}
                };

                result
            }
            &mut AuthSession::System {
                ref account_id,
                id: _,
                ref mut cred_handler,
                ref shadow,
            } => {
                // I had a lot of thoughts here, but I think system auth is
                // not the same as provider, so I think we special case here and have a separate
                // return type.
                let system_auth_result = shadow.auth_step(cred_handler, pam_next_req);

                let next = match system_auth_result {
                    SystemAuthResult::Denied => {
                        info!(?account_id, "Authentication Denied");

                        *auth_session = AuthSession::Denied;

                        Ok(PamAuthResponse::Denied)
                    }
                    SystemAuthResult::Success => {
                        info!(?account_id, "Authentication Success");

                        *auth_session = AuthSession::Success;

                        Ok(PamAuthResponse::Success)
                    }
                    SystemAuthResult::Next(req) => Ok(req.into()),
                };

                // We shortcut here
                return next;
            }
            &mut AuthSession::Success | &mut AuthSession::Denied => Err(IdpError::BadRequest),
        };

        match maybe_err {
            // What did the provider direct us to do next?
            Ok(AuthResult::Success) => {
                *auth_session = AuthSession::Success;
                Ok(PamAuthResponse::Success)
            }
            Ok(AuthResult::SuccessUpdate { mut new_token }) => {
                self.set_cache_usertoken(&mut new_token, hsm_lock.deref_mut())
                    .await?;
                *auth_session = AuthSession::Success;

                Ok(PamAuthResponse::Success)
            }
            Ok(AuthResult::Denied) => {
                *auth_session = AuthSession::Denied;

                Ok(PamAuthResponse::Denied)
            }
            Ok(AuthResult::Next(req)) => Ok(req.into()),
            Err(IdpError::NotFound) => {
                *auth_session = AuthSession::Denied;

                Ok(PamAuthResponse::Unknown)
            }
            Err(err) => {
                *auth_session = AuthSession::Denied;

                error!(?err, "Unable to proceed, failing the session");
                Err(())
            }
        }
    }

    // Can this be cfg debug/test?
    #[instrument(level = "debug", skip(self, password, current_time))]
    pub async fn pam_account_authenticate(
        &self,
        account_id: &str,
        current_time: OffsetDateTime,
        password: &str,
    ) -> Result<Option<bool>, ()> {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let pam_info = PamServiceInfo {
            service: "kanidm-unix-test".to_string(),
            tty: Some("/dev/null".to_string()),
            rhost: None,
        };

        let mut auth_session = match self
            .pam_account_authenticate_init(account_id, &pam_info, current_time, shutdown_rx)
            .await?
        {
            (auth_session, PamAuthResponse::Password) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::DeviceAuthorizationGrant { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFACode { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFAPoll { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFAPollWait) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::SetupPin { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::Pin) => {
                // Can continue!
                auth_session
            }
            (_, PamAuthResponse::Unknown) => return Ok(None),
            (_, PamAuthResponse::Denied) => return Ok(Some(false)),
            (_, PamAuthResponse::Success) => {
                // Should never get here "off the rip".
                debug_assert!(false);
                return Ok(Some(true));
            }
        };

        // Now we can make the next step.
        let pam_next_req = PamAuthRequest::Password {
            cred: password.to_string(),
        };
        match self
            .pam_account_authenticate_step(&mut auth_session, pam_next_req)
            .await?
        {
            PamAuthResponse::Success => Ok(Some(true)),
            PamAuthResponse::Denied => Ok(Some(false)),
            _ => {
                // Should not be able to get here, if the user was unknown they should
                // be out. If it wants more mechanisms, we can't proceed here.
                // debug_assert!(false);
                Ok(None)
            }
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn pam_account_beginsession(
        &self,
        account_id: &str,
    ) -> Result<Option<HomeDirectoryInfo>, ()> {
        let current_time = SystemTime::now();
        let id = Id::Name(account_id.to_string());

        match self.system_provider.begin_session(&id).await {
            SystemProviderSession::Start => {
                return Ok(None);
            }
            /*
            SystemProviderSession::StartCreateHome(
                info
            ) => {
                return Ok(Some(info));
            }
            */
            SystemProviderSession::Ignore => {}
        };

        // Not a system account, check based on the token and resolve.
        let token = self.get_usertoken(&id, current_time).await?;
        Ok(token.as_ref().map(|tok| HomeDirectoryInfo {
            uid: tok.gidnumber,
            gid: tok.gidnumber,
            name: self.token_homedirectory_attr(tok),
            aliases: self
                .token_homedirectory_alias(tok)
                .map(|s| vec![s])
                .unwrap_or_default(),
        }))
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn provider_status(&self) -> Vec<ProviderStatus> {
        let now = SystemTime::now();
        let mut hsm_lock = self.hsm.lock().await;

        let mut results = Vec::with_capacity(self.clients.len() + 1);

        results.push(ProviderStatus {
            name: "system".to_string(),
            online: true,
        });

        for client in self.clients.iter() {
            let online = client.attempt_online(hsm_lock.deref_mut(), now).await;

            let name = client.origin().to_string();

            results.push(ProviderStatus { name, online })
        }

        results
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn test_connection(&self) -> bool {
        let now = SystemTime::now();
        let mut hsm_lock = self.hsm.lock().await;

        for client in self.clients.iter() {
            let status = client.attempt_online(hsm_lock.deref_mut(), now).await;

            if !status {
                return false;
            }
        }

        // All online
        true
    }
}
