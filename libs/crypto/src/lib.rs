#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::unreachable)]

use base64::{
    alphabet,
    engine::{general_purpose, GeneralPurpose},
    Engine,
};
use base64urlsafedata::Base64UrlSafeData;
use crypto_glue::{
    argon2::{Algorithm, Argon2, Params, PasswordHash, Version},
    pbkdf2::pbkdf2_hmac,
    s256::Sha256,
    s512::Sha512,
    sha1::Sha1,
    traits::Digest,
};
use kanidm_hsm_crypto::{provider::TpmHmacS256, structures::HmacS256Key};
use md4::Md4;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fmt::Display,
    num::ParseIntError,
    time::{Duration, Instant},
};
use tracing::{debug, error, warn};

mod crypt_md5;

pub use sha2;

// Per https://pages.nist.gov/800-63-4/sp800-63b.html max length should be 64. This is
// measured in GRAPHEMES, not bytes.
pub const PW_MAX_LENGTH_NIST: u32 = 128;

// Single factor passwords have a greater minimum length requirement per nist.
pub const PW_SFA_MIN_LENGTH_NIST: u32 = 15;
// When used with MFA, the MIN length can be relaxed. Per NIST 8 is acceptable, but we
// have used 10 for this value.
pub const PW_MFA_MIN_LENGTH: u32 = 10;

// Since we added a max length constraint later, we should continue to allow long
// passwords to be validated. NOTE this is BYTES not GRAPHEMES.
pub const PW_MAX_LENGTH_CHECK: usize = PW_MAX_LENGTH_NIST as usize * 4;

// NIST 800-63.b salt should be 112 bits -> 14  8u8.
const PBKDF2_SALT_LEN: usize = 24;

pub const PBKDF2_MIN_NIST_SALT_LEN: usize = 14;

// Min number of rounds for a pbkdf2
pub const PBKDF2_MIN_NIST_COST: u32 = 10_000;
// Default rounds - owasp recommend 600_000 rounds.
pub const PBKDF2_DEFAULT_COST: u32 = 600_000;

// 32 * u8 -> 256 bits of out.
const PBKDF2_KEY_LEN: usize = 32;
const PBKDF2_MIN_NIST_KEY_LEN: usize = 32;
const PBKDF2_SHA1_MIN_KEY_LEN: usize = 19;

const DS_SHA1_HASH_LEN: usize = 20;
const DS_SHA256_HASH_LEN: usize = 32;
const DS_SHA512_HASH_LEN: usize = 64;

// Taken from the argon2 library and rfc 9106
const ARGON2_VERSION: u32 = 19;
const ARGON2_SALT_LEN: usize = 16;
// 32 * u8 -> 256 bits of out.
const ARGON2_KEY_LEN: usize = 32;
// Default amount of ram we sacrifice per thread
const ARGON2_MIN_RAM_KIB: u32 = 8 * 1024;
const ARGON2_MAX_RAM_KIB: u32 = 64 * 1024;
// Amount of ram to subtract when we do a T cost iter. This
// is because t=2 m=32 == t=3 m=20. So we just step down a little
// to keep the value about the same.
const ARGON2_TCOST_RAM_ITER_KIB: u32 = 12 * 1024;
const ARGON2_MIN_T_COST: u32 = 2;
const ARGON2_MAX_T_COST: u32 = 16;
const ARGON2_MAX_P_COST: u32 = 1;

#[derive(Clone, Debug)]
pub enum CryptoError {
    Hsm,
    HsmContextMissing,
    OpenSSL(u64),
    Md4Disabled,
    Argon2,
    Argon2Version,
    Argon2Parameters,
    Crypt,
    InvalidServerName,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
pub enum DbPasswordV1 {
    TPM_ARGON2ID {
        m: u32,
        t: u32,
        p: u32,
        v: u32,
        s: Base64UrlSafeData,
        k: Base64UrlSafeData,
    },
    ARGON2ID {
        m: u32,
        t: u32,
        p: u32,
        v: u32,
        s: Base64UrlSafeData,
        k: Base64UrlSafeData,
    },
    PBKDF2(u32, Vec<u8>, Vec<u8>),
    PBKDF2_SHA1(u32, Vec<u8>, Vec<u8>),
    PBKDF2_SHA512(u32, Vec<u8>, Vec<u8>),
    SHA1(Vec<u8>),
    SSHA1(Vec<u8>, Vec<u8>),
    SHA256(Vec<u8>),
    SSHA256(Vec<u8>, Vec<u8>),
    SHA512(Vec<u8>),
    SSHA512(Vec<u8>, Vec<u8>),
    NT_MD4(Vec<u8>),
    CRYPT_MD5 {
        s: Base64UrlSafeData,
        h: Base64UrlSafeData,
    },
    CRYPT_SHA256 {
        h: String,
    },
    CRYPT_SHA512 {
        h: String,
    },
}

impl fmt::Debug for DbPasswordV1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbPasswordV1::TPM_ARGON2ID { .. } => write!(f, "TPM_ARGON2ID"),
            DbPasswordV1::ARGON2ID { .. } => write!(f, "ARGON2ID"),
            DbPasswordV1::PBKDF2(_, _, _) => write!(f, "PBKDF2"),
            DbPasswordV1::PBKDF2_SHA1(_, _, _) => write!(f, "PBKDF2_SHA1"),
            DbPasswordV1::PBKDF2_SHA512(_, _, _) => write!(f, "PBKDF2_SHA512"),
            DbPasswordV1::SHA1(_) => write!(f, "SHA1"),
            DbPasswordV1::SSHA1(_, _) => write!(f, "SSHA1"),
            DbPasswordV1::SHA256(_) => write!(f, "SHA256"),
            DbPasswordV1::SSHA256(_, _) => write!(f, "SSHA256"),
            DbPasswordV1::SHA512(_) => write!(f, "SHA512"),
            DbPasswordV1::SSHA512(_, _) => write!(f, "SSHA512"),
            DbPasswordV1::NT_MD4(_) => write!(f, "NT_MD4"),
            DbPasswordV1::CRYPT_MD5 { .. } => write!(f, "CRYPT_MD5"),
            DbPasswordV1::CRYPT_SHA256 { .. } => write!(f, "CRYPT_SHA256"),
            DbPasswordV1::CRYPT_SHA512 { .. } => write!(f, "CRYPT_SHA512"),
        }
    }
}

#[derive(Debug)]
pub struct CryptoPolicy {
    pub(crate) pbkdf2_cost: u32,
    // https://docs.rs/argon2/0.5.0/argon2/struct.Params.html
    // defaults to 19mb memory, 2 iterations and 1 thread, with a 32byte output.
    pub(crate) argon2id_params: Params,
}

impl CryptoPolicy {
    pub fn minimum() -> Self {
        CryptoPolicy {
            pbkdf2_cost: PBKDF2_MIN_NIST_COST,
            argon2id_params: Params::default(),
        }
    }

    pub fn danger_test_minimum() -> Self {
        CryptoPolicy {
            pbkdf2_cost: 1000,
            argon2id_params: Params::new(
                Params::MIN_M_COST,
                Params::MIN_T_COST,
                Params::MIN_P_COST,
                None,
            )
            .unwrap_or_default(),
        }
    }

    pub fn time_target(target_time: Duration) -> Self {
        // Argon2id has multiple parameters. These all are about *exchanges* that you can
        // request in how the computation is performed.
        //
        // rfc9106 explains that there are two algorithms stacked here. Argon2i has defences
        // against side-channel timing. Argon2d provides defences for time-memory tradeoffs.
        //
        // We can see how this impacts timings from sources like:
        // https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
        //
        // M =  256 MB, T =    2, d = 8, Time = 0.732 s
        // M =  128 MB, T =    6, d = 8, Time = 0.99 s
        // M =   64 MB, T =   12, d = 8, Time = 0.968 s
        // M =   32 MB, T =   24, d = 8, Time = 0.896 s
        // M =   16 MB, T =   49, d = 8, Time = 0.973 s
        // M =    8 MB, T =   96, d = 8, Time = 0.991 s
        // M =    4 MB, T =  190, d = 8, Time = 0.977 s
        // M =    2 MB, T =  271, d = 8, Time = 0.973 s
        // M =    1 MB, T =  639, d = 8, Time = 0.991 s
        //
        // As we can see, the time taken stays constant, but as ram decreases the amount of
        // CPU work required goes up. In our case, our primary threat is from GPU hashcat
        // cracking. GPU's tend to have many fast cores but very little amounts of fast ram
        // for those cores. So we want to have as much ram as *possible* up to a limit, and
        // then we want to increase iterations.
        //
        // This way a GPU has to expend further GPU time to compensate for the less ram.
        //
        // We also need to balance this against the fact we are a database, and we do have
        // caches. We also don't want to over-use RAM, especially because in the worst case
        // every thread will be operating in argon2id at the same time. That means
        // thread x ram will be used. If we had 8 threads at 64mb of ram, that would require
        // 512mb of ram alone just for hashing. This becomes worse as core counts scale, with
        // 24 core xeons easily reaching 1.5GB in these cases.

        let mut m_cost = ARGON2_MIN_RAM_KIB;
        let mut t_cost = ARGON2_MIN_T_COST;
        let p_cost = ARGON2_MAX_P_COST;

        // Raise memory usage until an acceptable ram amount is reached.
        loop {
            let params = if let Ok(p) = Params::new(m_cost, t_cost, p_cost, None) {
                p
            } else {
                // Unable to proceed.
                error!(
                    ?m_cost,
                    ?t_cost,
                    ?p_cost,
                    "Parameters were not valid for argon2"
                );
                break;
            };

            if let Some(ubt) = Password::bench_argon2id(params) {
                debug!("{}ns - t_cost {} m_cost {}", ubt.as_nanos(), t_cost, m_cost);
                // Parameter adjustment
                if ubt < target_time {
                    let m_mult = target_time
                        .as_nanos()
                        .checked_div(ubt.as_nanos())
                        .unwrap_or(1);
                    if m_cost < ARGON2_MAX_RAM_KIB {
                        // Help narrow in quicker.
                        let m_adjust = if m_mult >= 2 {
                            // Far away, multiply up
                            m_cost * u32::try_from(m_mult).unwrap_or(2)
                        } else {
                            // Close! Increase in a small step
                            m_cost + 1024
                        };

                        m_cost = if m_adjust > ARGON2_MAX_RAM_KIB {
                            ARGON2_MAX_RAM_KIB
                        } else {
                            m_adjust
                        };
                        continue;
                    } else if t_cost < ARGON2_MAX_T_COST {
                        // Help narrow in quicker.
                        if m_mult >= 2 {
                            // Far away, multiply T next
                            let t_adjust = t_cost * u32::try_from(m_mult).unwrap_or(2);
                            t_cost = t_adjust.clamp(ARGON2_MIN_T_COST, ARGON2_MAX_T_COST);
                        } else {
                            // t=2 with m = 32MB is about the same as t=3 m=20MB, so we want to start with ram
                            // higher on these iterations. About 12MB appears to be one iteration. We use 8MB
                            // here though, just to give a little window under that for adjustment.
                            //
                            // Similar, once we hit t=4 we just need to have max ram.
                            t_cost += 1;
                            // Halve the ram cost.
                            let m_adjust = m_cost
                                .checked_sub(ARGON2_TCOST_RAM_ITER_KIB)
                                .unwrap_or(ARGON2_MIN_RAM_KIB);

                            // Clamp the value
                            m_cost = m_adjust.clamp(ARGON2_MIN_RAM_KIB, ARGON2_MAX_RAM_KIB);
                        }
                        continue;
                    } else {
                        // Unable to proceed, parameters are maxed out.
                        warn!("Argon2 parameters have hit their maximums - this may be a bug!");
                        break;
                    }
                } else {
                    // Found the target time.
                    break;
                }
            } else {
                error!("Unable to perform bench of argon2id, stopping benchmark");
                break;
            }
        }

        let argon2id_params = Params::new(m_cost, t_cost, p_cost, None)
            // fallback
            .unwrap_or_default();

        let p = CryptoPolicy {
            pbkdf2_cost: PBKDF2_DEFAULT_COST,
            argon2id_params,
        };
        debug!(argon2id_m = %p.argon2id_params.m_cost(), argon2id_p = %p.argon2id_params.p_cost(), argon2id_t = %p.argon2id_params.t_cost(), );
        p
    }
}

// Why PBKDF2? Rust's bcrypt has a number of hardcodings like max pw len of 72
// I don't really feel like adding in so many restrictions, so I'll use
// pbkdf2 in openssl because it doesn't have the same limits.
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
enum Kdf {
    TPM_ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Vec<u8>,
        key: Vec<u8>,
    },
    //
    ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Vec<u8>,
        key: Vec<u8>,
    },
    //     cost, salt,   hash
    PBKDF2(u32, Vec<u8>, Vec<u8>),

    // Imported types, will upgrade to the above.
    //         cost,   salt,    hash
    PBKDF2_SHA1(u32, Vec<u8>, Vec<u8>),
    //           cost,   salt,    hash
    PBKDF2_SHA512(u32, Vec<u8>, Vec<u8>),
    //      salt     hash
    SHA1(Vec<u8>),
    SSHA1(Vec<u8>, Vec<u8>),
    SHA256(Vec<u8>),
    SSHA256(Vec<u8>, Vec<u8>),
    SHA512(Vec<u8>),
    SSHA512(Vec<u8>, Vec<u8>),
    //     hash
    NT_MD4(Vec<u8>),
    CRYPT_MD5 {
        s: Vec<u8>,
        h: Vec<u8>,
    },
    CRYPT_SHA256 {
        h: String,
    },
    CRYPT_SHA512 {
        h: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PasswordError {
    Base64Decoding,
    InvalidFormat,
    InvalidKeyLength,
    InvalidLength,
    InvalidSaltLength,
    // We guess what it is, but don't know how to handle it
    UnsupportedAlgorithm(String),
    // No idea how to decode this password
    NoDecoderFound(String),
    ParsingFailed,
}

impl Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::Base64Decoding => write!(f, "Base64 decoding failed"),
            PasswordError::InvalidFormat => write!(f, "Invalid password format"),
            PasswordError::InvalidKeyLength => write!(f, "Invalid key length for password"),
            PasswordError::InvalidLength => write!(f, "Invalid length for password"),
            PasswordError::InvalidSaltLength => write!(f, "Invalid salt length for password"),
            PasswordError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported algorithm: {alg}")
            }
            PasswordError::NoDecoderFound(hint) => {
                write!(f, "No decoder found for password in this format - input started with '{hint}' - please report it upstream")
            }
            PasswordError::ParsingFailed => write!(f, "Parsing of password failed"),
        }
    }
}

impl From<ParseIntError> for PasswordError {
    fn from(_err: ParseIntError) -> Self {
        PasswordError::ParsingFailed
    }
}

impl From<base64::DecodeError> for PasswordError {
    fn from(_err: base64::DecodeError) -> Self {
        PasswordError::Base64Decoding
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Password {
    material: Kdf,
}

impl TryFrom<DbPasswordV1> for Password {
    type Error = ();

    fn try_from(value: DbPasswordV1) -> Result<Self, Self::Error> {
        match value {
            DbPasswordV1::TPM_ARGON2ID { m, t, p, v, s, k } => Ok(Password {
                material: Kdf::TPM_ARGON2ID {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p,
                    version: v,
                    salt: s.into(),
                    key: k.into(),
                },
            }),
            DbPasswordV1::ARGON2ID { m, t, p, v, s, k } => Ok(Password {
                material: Kdf::ARGON2ID {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p,
                    version: v,
                    salt: s.into(),
                    key: k.into(),
                },
            }),
            DbPasswordV1::PBKDF2(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2(c, s, h),
            }),
            DbPasswordV1::PBKDF2_SHA1(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2_SHA1(c, s, h),
            }),
            DbPasswordV1::PBKDF2_SHA512(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2_SHA512(c, s, h),
            }),
            DbPasswordV1::SHA1(h) => Ok(Password {
                material: Kdf::SHA1(h),
            }),
            DbPasswordV1::SSHA1(s, h) => Ok(Password {
                material: Kdf::SSHA1(s, h),
            }),
            DbPasswordV1::SHA256(h) => Ok(Password {
                material: Kdf::SHA256(h),
            }),
            DbPasswordV1::SSHA256(s, h) => Ok(Password {
                material: Kdf::SSHA256(s, h),
            }),
            DbPasswordV1::SHA512(h) => Ok(Password {
                material: Kdf::SHA512(h),
            }),
            DbPasswordV1::SSHA512(s, h) => Ok(Password {
                material: Kdf::SSHA512(s, h),
            }),
            DbPasswordV1::NT_MD4(h) => Ok(Password {
                material: Kdf::NT_MD4(h),
            }),
            DbPasswordV1::CRYPT_MD5 { s, h } => Ok(Password {
                material: Kdf::CRYPT_MD5 {
                    s: s.into(),
                    h: h.into(),
                },
            }),
            DbPasswordV1::CRYPT_SHA256 { h } => Ok(Password {
                material: Kdf::CRYPT_SHA256 { h },
            }),
            DbPasswordV1::CRYPT_SHA512 { h } => Ok(Password {
                material: Kdf::CRYPT_SHA256 { h },
            }),
        }
    }
}

// OpenLDAP based their PBKDF2 implementation on passlib from python, that uses a
// non-standard base64 altchar set and padding that is not supported by
// anything else in the world. To manage this, we only ever encode to base64 with
// no pad but we have to remap ab64 to b64. This function allows b64 standard with
// padding to pass, and remaps ab64 to b64 standard with padding.
macro_rules! ab64_to_b64 {
    ($ab64:expr) => {{
        let mut s = $ab64.replace(".", "+");
        match s.len() & 3 {
            0 => {
                // Do nothing
            }
            1 => {
                // One is invalid, do nothing, we'll error in base64
            }
            2 => s.push_str("=="),
            3 => s.push_str("="),
            _ => unreachable!(),
        }
        s
    }};
}

/// Django passwords look like `algo$salt$hash`
fn parse_django_password(value: &str) -> Result<Password, PasswordError> {
    let django_pbkdf: Vec<&str> = value.split('$').collect();
    if django_pbkdf.len() != 4 {
        return Err(PasswordError::InvalidLength);
    }
    // let _algo = django_pbkdf[0];
    let cost = django_pbkdf[1];
    let salt = django_pbkdf[2];
    let hash = django_pbkdf[3];
    let c = cost.parse::<u32>()?;
    let s: Vec<_> = salt.as_bytes().to_vec();
    let h = general_purpose::STANDARD.decode(hash)?;
    if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
        Err(PasswordError::InvalidLength)
    } else {
        Ok(Password {
            material: Kdf::PBKDF2(c, s, h),
        })
    }
}

fn parse_ipanthash(hash_value: &str) -> Result<Password, PasswordError> {
    // Great work.
    let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(hash_value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(hash_value))?;

    Ok(Password {
        material: Kdf::NT_MD4(h),
    })
}

fn parse_sambantpassword(hash_value: &str) -> Result<Password, PasswordError> {
    let h = hex::decode(hash_value).map_err(|_| PasswordError::ParsingFailed)?;
    Ok(Password {
        material: Kdf::NT_MD4(h),
    })
}

fn parse_crypt(hash_value: &str) -> Result<Password, PasswordError> {
    if let Some(crypt_md5_phc) = hash_value.strip_prefix("$1$") {
        let (salt, hash) = crypt_md5_phc
            .split_once('$')
            .ok_or(PasswordError::ParsingFailed)?;

        // These are a hash64 format, so leave them as bytes, don't try
        // to decode.
        let s = salt.as_bytes().to_vec();
        let h = hash.as_bytes().to_vec();

        Ok(Password {
            material: Kdf::CRYPT_MD5 { s, h },
        })
    } else if hash_value.starts_with("$5$") {
        Ok(Password {
            material: Kdf::CRYPT_SHA256 {
                h: hash_value.to_string(),
            },
        })
    } else if hash_value.starts_with("$6$") {
        Ok(Password {
            material: Kdf::CRYPT_SHA512 {
                h: hash_value.to_string(),
            },
        })
    } else {
        Err(PasswordError::UnsupportedAlgorithm("crypt".to_string()))
    }
}

fn parse_pbkdf2(hash_format: &str, hash_value: &str) -> Result<Password, PasswordError> {
    let ol_pbkdf: Vec<&str> = hash_value.split('$').collect();
    if ol_pbkdf.len() != 3 {
        warn!("oldap pbkdf2 found but invalid number of elements?");
        return Err(PasswordError::InvalidLength);
    }

    let cost = ol_pbkdf[0];
    let salt = ol_pbkdf[1];
    let hash = ol_pbkdf[2];

    let c: u32 = cost.parse()?;

    let s = ab64_to_b64!(salt);
    let base64_decoder_config =
        general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true);
    let base64_decoder = GeneralPurpose::new(&alphabet::STANDARD, base64_decoder_config);
    let s = base64_decoder.decode(s).inspect_err(|e| {
        error!(?e, "Invalid base64 in oldap pbkdf2-sha1");
    })?;

    let h = ab64_to_b64!(hash);
    let h = base64_decoder.decode(h).inspect_err(|e| {
        error!(?e, "Invalid base64 in oldap pbkdf2-sha1");
    })?;

    match hash_format {
        // This is just sha1 in a trenchcoat.
        "pbkdf2" | "pbkdf2-sha1" => {
            if h.len() < PBKDF2_SHA1_MIN_KEY_LEN {
                Err(PasswordError::InvalidKeyLength)
            } else {
                Ok(Password {
                    material: Kdf::PBKDF2_SHA1(c, s, h),
                })
            }
        }
        "pbkdf2-sha256" => {
            if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
                Err(PasswordError::InvalidKeyLength)
            } else {
                Ok(Password {
                    material: Kdf::PBKDF2(c, s, h),
                })
            }
        }
        "pbkdf2-sha512" => {
            if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
                Err(PasswordError::InvalidKeyLength)
            } else {
                Ok(Password {
                    material: Kdf::PBKDF2_SHA512(c, s, h),
                })
            }
        }
        _ => Err(PasswordError::UnsupportedAlgorithm(hash_format.to_string())),
    }
}

fn parse_argon(hash_value: &str) -> Result<Password, PasswordError> {
    match PasswordHash::try_from(hash_value) {
        Ok(PasswordHash {
            algorithm,
            version,
            params,
            salt,
            hash,
        }) => {
            if algorithm.as_str() != "argon2id" {
                error!(alg = %algorithm.as_str(), "Only argon2id is supported");
                return Err(PasswordError::UnsupportedAlgorithm(algorithm.to_string()));
            }

            let version = version.unwrap_or(ARGON2_VERSION);
            let version: Version = version.try_into().map_err(|_| {
                error!("Failed to convert {} to valid argon2id version", version);
                PasswordError::ParsingFailed
            })?;

            let m_cost = params.get_decimal("m").ok_or_else(|| {
                error!("Failed to access m_cost parameter");
                PasswordError::ParsingFailed
            })?;

            let t_cost = params.get_decimal("t").ok_or_else(|| {
                error!("Failed to access t_cost parameter");
                PasswordError::ParsingFailed
            })?;

            let p_cost = params.get_decimal("p").ok_or_else(|| {
                error!("Failed to access p_cost parameter");
                PasswordError::ParsingFailed
            })?;

            let salt = salt.map(|s| s.to_vec()).ok_or_else(|| {
                error!("Failed to access salt");
                PasswordError::ParsingFailed
            })?;

            let key = hash.map(|h| h.as_bytes().into()).ok_or_else(|| {
                error!("Failed to access key");
                PasswordError::ParsingFailed
            })?;

            Ok(Password {
                material: Kdf::ARGON2ID {
                    m_cost,
                    t_cost,
                    p_cost,
                    version: version as u32,
                    salt,
                    key,
                },
            })
        }
        Err(e) => {
            error!(?e, "Invalid argon2 PHC string");
            Err(PasswordError::ParsingFailed)
        }
    }
}

impl TryFrom<&str> for Password {
    type Error = PasswordError;

    // As we may add more algos, we keep the match algo single for later.

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.starts_with("pbkdf2_sha256$") {
            parse_django_password(value)
        } else if let Some(hash_value) = value.strip_prefix("ipaNTHash: ") {
            parse_ipanthash(hash_value)
        } else if let Some(hash_value) = value.strip_prefix("sambaNTPassword: ") {
            parse_sambantpassword(hash_value)
        } else if value.starts_with("{") {
            // Test 389ds/openldap formats. Shout outs openldap which sometimes makes these
            // lowercase, so we're making them all lowercase!

            // turn {hash_format}hash_value into hash_format and hash_value (and lowercase hash_format)
            let (hash_format, hash_value) = match value.split_once('}') {
                Some((format, value)) => (
                    format.strip_prefix('{').unwrap_or(format).to_lowercase(),
                    value,
                ),
                None => {
                    return Err(PasswordError::InvalidFormat);
                }
            };

            match hash_format.as_str() {
                // Test for OpenLDAP formats
                "pbkdf2" | "pbkdf2-sha1" | "pbkdf2-sha256" | "pbkdf2-sha512" => {
                    parse_pbkdf2(&hash_format, hash_value)
                }

                // This is the binary version of 389-ds pbkdf2 which we do not support.
                "pbkdf2_sha256" => Err(PasswordError::InvalidFormat),

                "argon2" => parse_argon(hash_value),
                "crypt" => parse_crypt(hash_value),
                "sha" => {
                    let h = general_purpose::STANDARD.decode(hash_value)?;
                    if h.len() != DS_SHA1_HASH_LEN {
                        return Err(PasswordError::InvalidSaltLength);
                    }
                    Ok(Password {
                        material: Kdf::SHA1(h.to_vec()),
                    })
                }
                "ssha" => {
                    let sh = general_purpose::STANDARD.decode(hash_value)?;
                    let (h, s) = sh
                        .split_at_checked(DS_SHA1_HASH_LEN)
                        .ok_or(PasswordError::InvalidLength)?;

                    Ok(Password {
                        material: Kdf::SSHA1(s.to_vec(), h.to_vec()),
                    })
                }
                "sha256" => {
                    let h = general_purpose::STANDARD.decode(hash_value)?;
                    if h.len() != DS_SHA256_HASH_LEN {
                        return Err(PasswordError::InvalidSaltLength);
                    }
                    Ok(Password {
                        material: Kdf::SHA256(h.to_vec()),
                    })
                }
                "ssha256" => {
                    let sh = general_purpose::STANDARD.decode(hash_value)?;
                    let (h, s) = sh
                        .split_at_checked(DS_SHA256_HASH_LEN)
                        .ok_or(PasswordError::InvalidLength)?;
                    Ok(Password {
                        material: Kdf::SSHA256(s.to_vec(), h.to_vec()),
                    })
                }
                "sha512" => {
                    let h = general_purpose::STANDARD.decode(hash_value)?;
                    if h.len() != DS_SHA512_HASH_LEN {
                        return Err(PasswordError::InvalidSaltLength);
                    }
                    Ok(Password {
                        material: Kdf::SHA512(h.to_vec()),
                    })
                }
                "ssha512" => {
                    let sh = general_purpose::STANDARD.decode(hash_value)?;
                    if sh.len() <= DS_SHA512_HASH_LEN {
                        return Err(PasswordError::InvalidSaltLength);
                    }
                    let (h, s) = sh
                        .split_at_checked(DS_SHA512_HASH_LEN)
                        .ok_or(PasswordError::InvalidLength)?;
                    Ok(Password {
                        material: Kdf::SSHA512(s.to_vec(), h.to_vec()),
                    })
                }
                _ => Err(PasswordError::NoDecoderFound(hash_format)),
            }
        } else {
            Err(PasswordError::NoDecoderFound(
                value.chars().take(5).collect(),
            ))
        }
    }
}

impl Password {
    fn bench_argon2id(params: Params) -> Option<Duration> {
        let mut rng = rand::rng();
        let salt: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.random()).collect();
        let input: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.random()).collect();
        let mut key: Vec<u8> = (0..ARGON2_KEY_LEN).map(|_| 0).collect();

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let start = Instant::now();
        argon
            .hash_password_into(input.as_slice(), salt.as_slice(), key.as_mut_slice())
            .ok()?;
        let end = Instant::now();

        end.checked_duration_since(start)
    }

    pub fn new_pbkdf2(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        let pbkdf2_cost = policy.pbkdf2_cost;
        let mut rng = rand::rng();
        let salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.random()).collect();
        let mut key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();

        pbkdf2_hmac::<Sha256>(
            cleartext.as_bytes(),
            salt.as_slice(),
            pbkdf2_cost,
            key.as_mut_slice(),
        );

        // Turn key to a vec.
        Ok(Password {
            material: Kdf::PBKDF2(pbkdf2_cost, salt, key),
        })
    }

    pub fn new_argon2id(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        let version = Version::V0x13;

        let argon = Argon2::new(Algorithm::Argon2id, version, policy.argon2id_params.clone());

        let mut rng = rand::rng();
        let salt: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.random()).collect();
        let mut key: Vec<u8> = (0..ARGON2_KEY_LEN).map(|_| 0).collect();

        argon
            .hash_password_into(cleartext.as_bytes(), salt.as_slice(), key.as_mut_slice())
            .map(|()| Kdf::ARGON2ID {
                m_cost: policy.argon2id_params.m_cost(),
                t_cost: policy.argon2id_params.t_cost(),
                p_cost: policy.argon2id_params.p_cost(),
                version: version as u32,
                salt,
                key,
            })
            .map_err(|_| CryptoError::Argon2)
            .map(|material| Password { material })
    }

    pub fn new_argon2id_hsm(
        policy: &CryptoPolicy,
        cleartext: &str,
        hsm: &mut dyn TpmHmacS256,
        hmac_key: &HmacS256Key,
    ) -> Result<Self, CryptoError> {
        let version = Version::V0x13;

        let argon = Argon2::new(Algorithm::Argon2id, version, policy.argon2id_params.clone());

        let mut rng = rand::rng();
        let salt: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.random()).collect();
        let mut check_key: Vec<u8> = (0..ARGON2_KEY_LEN).map(|_| 0).collect();

        argon
            .hash_password_into(
                cleartext.as_bytes(),
                salt.as_slice(),
                check_key.as_mut_slice(),
            )
            .map_err(|_| CryptoError::Argon2)
            .and_then(|()| {
                hsm.hmac_s256(hmac_key, &check_key)
                    .map_err(|err| {
                        error!(?err, "hsm error");
                        CryptoError::Hsm
                    })
                    .map(|hmac_output| hmac_output.into_bytes().to_vec())
            })
            .map(|key| Kdf::TPM_ARGON2ID {
                m_cost: policy.argon2id_params.m_cost(),
                t_cost: policy.argon2id_params.t_cost(),
                p_cost: policy.argon2id_params.p_cost(),
                version: version as u32,
                salt,
                key,
            })
            .map(|material| Password { material })
    }

    #[inline]
    pub fn new(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        Self::new_argon2id(policy, cleartext)
    }

    pub fn verify(&self, cleartext: &str) -> Result<bool, CryptoError> {
        self.verify_ctx(cleartext, None)
    }

    pub fn verify_ctx(
        &self,
        cleartext: &str,
        hsm: Option<(&mut dyn TpmHmacS256, &HmacS256Key)>,
    ) -> Result<bool, CryptoError> {
        if cleartext.len() > PW_MAX_LENGTH_CHECK {
            error!("Cleartext input exceeds safe KDF length {PW_MAX_LENGTH_CHECK}, refusing to proceed.");
            return Ok(false);
        }

        match (&self.material, hsm) {
            (
                Kdf::TPM_ARGON2ID {
                    m_cost,
                    t_cost,
                    p_cost,
                    version,
                    salt,
                    key,
                },
                Some((hsm, hmac_key)),
            ) => {
                let version: Version = (*version).try_into().map_err(|_| {
                    error!("Failed to convert {} to valid argon2id version", version);
                    CryptoError::Argon2Version
                })?;

                let key_len = key.len();

                let params =
                    Params::new(*m_cost, *t_cost, *p_cost, Some(key_len)).map_err(|e| {
                        error!(err = ?e, "invalid argon2id parameters");
                        CryptoError::Argon2Parameters
                    })?;

                let argon = Argon2::new(Algorithm::Argon2id, version, params);
                let mut check_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                argon
                    .hash_password_into(
                        cleartext.as_bytes(),
                        salt.as_slice(),
                        check_key.as_mut_slice(),
                    )
                    .map_err(|e| {
                        error!(err = ?e, "unable to perform argon2id hash");
                        CryptoError::Argon2
                    })
                    .and_then(|()| {
                        hsm.hmac_s256(hmac_key, &check_key).map_err(|err| {
                            error!(?err, "hsm error");
                            CryptoError::Hsm
                        })
                    })
                    .map(|hmac_key| {
                        // Actually compare the outputs.
                        hmac_key.into_bytes().as_slice() == key
                    })
            }
            (Kdf::TPM_ARGON2ID { .. }, None) => {
                error!("Unable to validate password - not hsm context available");
                Err(CryptoError::HsmContextMissing)
            }
            (
                Kdf::ARGON2ID {
                    m_cost,
                    t_cost,
                    p_cost,
                    version,
                    salt,
                    key,
                },
                _,
            ) => {
                let version: Version = (*version).try_into().map_err(|_| {
                    error!("Failed to convert {} to valid argon2id version", version);
                    CryptoError::Argon2Version
                })?;

                let key_len = key.len();

                let params =
                    Params::new(*m_cost, *t_cost, *p_cost, Some(key_len)).map_err(|e| {
                        error!(err = ?e, "invalid argon2id parameters");
                        CryptoError::Argon2Parameters
                    })?;

                let argon = Argon2::new(Algorithm::Argon2id, version, params);
                let mut check_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                argon
                    .hash_password_into(
                        cleartext.as_bytes(),
                        salt.as_slice(),
                        check_key.as_mut_slice(),
                    )
                    .map_err(|e| {
                        error!(err = ?e, "unable to perform argon2id hash");
                        CryptoError::Argon2
                    })
                    .map(|()| {
                        // Actually compare the outputs.
                        &check_key == key
                    })
            }
            (Kdf::PBKDF2(cost, salt, key), _) => {
                // We have to get the number of bits to derive from our stored hash
                // as some imported hash types may have variable lengths
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_MIN_NIST_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                pbkdf2_hmac::<Sha256>(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    chal_key.as_mut_slice(),
                );

                // Actually compare the outputs.
                Ok(&chal_key == key)
            }
            (Kdf::PBKDF2_SHA1(cost, salt, key), _) => {
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_SHA1_MIN_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                pbkdf2_hmac::<Sha1>(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    chal_key.as_mut_slice(),
                );

                // Actually compare the outputs.
                Ok(&chal_key == key)
            }
            (Kdf::PBKDF2_SHA512(cost, salt, key), _) => {
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_MIN_NIST_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                pbkdf2_hmac::<Sha512>(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    chal_key.as_mut_slice(),
                );

                // Actually compare the outputs.
                Ok(&chal_key == key)
            }
            (Kdf::SHA1(key), _) => {
                let mut hasher = Sha1::new();
                hasher.update(cleartext.as_bytes());
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::SSHA1(salt, key), _) => {
                let mut hasher = Sha1::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(salt);
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::SHA256(key), _) => {
                let mut hasher = Sha256::new();
                hasher.update(cleartext.as_bytes());
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::SSHA256(salt, key), _) => {
                let mut hasher = Sha256::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(salt);
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::SHA512(key), _) => {
                let mut hasher = Sha512::new();
                hasher.update(cleartext.as_bytes());
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::SSHA512(salt, key), _) => {
                let mut hasher = Sha512::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(salt);
                let r = hasher.finalize();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::NT_MD4(key), _) => {
                // We need to get the cleartext to utf16le for reasons.
                let clear_utf16le: Vec<u8> = cleartext
                    .encode_utf16()
                    .map(|c| c.to_le_bytes())
                    .flat_map(|i| i.into_iter())
                    .collect();

                let mut hasher = Md4::new();
                hasher.update(&clear_utf16le);
                let chal_key = hasher.finalize();

                Ok(chal_key.as_slice() == key)
            }
            (Kdf::CRYPT_MD5 { s, h }, _) => {
                let chal_key = crypt_md5::do_md5_crypt(cleartext.as_bytes(), s);
                Ok(chal_key == *h)
            }
            (Kdf::CRYPT_SHA256 { h }, _) => {
                let is_valid = sha_crypt::sha256_check(cleartext, h.as_str()).is_ok();

                Ok(is_valid)
            }
            (Kdf::CRYPT_SHA512 { h }, _) => {
                let is_valid = sha_crypt::sha512_check(cleartext, h.as_str()).is_ok();

                Ok(is_valid)
            }
        }
    }

    pub fn to_dbpasswordv1(&self) -> DbPasswordV1 {
        match &self.material {
            Kdf::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => DbPasswordV1::TPM_ARGON2ID {
                m: *m_cost,
                t: *t_cost,
                p: *p_cost,
                v: *version,
                s: salt.clone().into(),
                k: key.clone().into(),
            },
            Kdf::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => DbPasswordV1::ARGON2ID {
                m: *m_cost,
                t: *t_cost,
                p: *p_cost,
                v: *version,
                s: salt.clone().into(),
                k: key.clone().into(),
            },
            Kdf::PBKDF2(cost, salt, hash) => {
                DbPasswordV1::PBKDF2(*cost, salt.clone(), hash.clone())
            }
            Kdf::PBKDF2_SHA1(cost, salt, hash) => {
                DbPasswordV1::PBKDF2_SHA1(*cost, salt.clone(), hash.clone())
            }
            Kdf::PBKDF2_SHA512(cost, salt, hash) => {
                DbPasswordV1::PBKDF2_SHA512(*cost, salt.clone(), hash.clone())
            }
            Kdf::SHA1(hash) => DbPasswordV1::SHA1(hash.clone()),
            Kdf::SSHA1(salt, hash) => DbPasswordV1::SSHA1(salt.clone(), hash.clone()),
            Kdf::SHA256(hash) => DbPasswordV1::SHA256(hash.clone()),
            Kdf::SSHA256(salt, hash) => DbPasswordV1::SSHA256(salt.clone(), hash.clone()),
            Kdf::SHA512(hash) => DbPasswordV1::SHA512(hash.clone()),
            Kdf::SSHA512(salt, hash) => DbPasswordV1::SSHA512(salt.clone(), hash.clone()),
            Kdf::NT_MD4(hash) => DbPasswordV1::NT_MD4(hash.clone()),
            Kdf::CRYPT_MD5 { s, h } => DbPasswordV1::CRYPT_MD5 {
                s: s.clone().into(),
                h: h.clone().into(),
            },
            Kdf::CRYPT_SHA256 { h } => DbPasswordV1::CRYPT_SHA256 { h: h.clone() },
            Kdf::CRYPT_SHA512 { h } => DbPasswordV1::CRYPT_SHA512 { h: h.clone() },
        }
    }

    pub fn requires_upgrade(&self) -> bool {
        match &self.material {
            Kdf::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => {
                *version < ARGON2_VERSION ||
                salt.len() < ARGON2_SALT_LEN ||
                key.len() < ARGON2_KEY_LEN ||
                // Can't multi-thread
                *p_cost > ARGON2_MAX_P_COST ||
                // Likely too long on cpu time.
                *t_cost > ARGON2_MAX_T_COST ||
                // Too much ram
                *m_cost > ARGON2_MAX_RAM_KIB
            }
            // Only used in unixd today
            Kdf::TPM_ARGON2ID { .. } => false,
            // All now upgraded to argon2id
            Kdf::PBKDF2(_, _, _)
            | Kdf::PBKDF2_SHA512(_, _, _)
            | Kdf::PBKDF2_SHA1(_, _, _)
            | Kdf::SHA1(_)
            | Kdf::SSHA1(_, _)
            | Kdf::SHA256(_)
            | Kdf::SSHA256(_, _)
            | Kdf::SHA512(_)
            | Kdf::SSHA512(_, _)
            | Kdf::NT_MD4(_)
            | Kdf::CRYPT_MD5 { .. }
            | Kdf::CRYPT_SHA256 { .. }
            | Kdf::CRYPT_SHA512 { .. } => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use kanidm_hsm_crypto::{
        provider::{SoftTpm, TpmHmacS256},
        AuthValue,
    };
    use std::convert::TryFrom;

    use crate::*;

    #[test]
    fn test_credential_simple() {
        let p = CryptoPolicy::minimum();
        let c = Password::new(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
        assert!(!c.verify("It Works!").unwrap());
        assert!(!c.verify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
    }

    #[test]
    fn test_password_pbkdf2() {
        let p = CryptoPolicy::minimum();
        let c = Password::new_pbkdf2(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
    }

    #[test]
    fn test_password_argon2id() {
        let p = CryptoPolicy::minimum();
        let c = Password::new_argon2id(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
    }

    #[test]
    fn test_password_from_invalid() {
        assert!(Password::try_from("password").is_err())
    }

    #[test]
    fn test_password_from_django_pbkdf2_sha256() {
        let im_pw = "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
        let password = "eicieY7ahchaoCh0eeTa";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_sha1() {
        let im_pw = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{sha}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_ssha1() {
        let im_pw = "{SSHA}EyzbBiP4u4zxOrLpKTORI/RX3HC6TCTJtnVOCQ==";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{ssha}EyzbBiP4u4zxOrLpKTORI/RX3HC6TCTJtnVOCQ==";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_sha256() {
        let im_pw = "{SHA256}XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{sha256}XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_ssha256() {
        let im_pw = "{SSHA256}luYWfFJOZgxySTsJXHgIaCYww4yMpu6yest69j/wO5n5OycuHFV/GQ==";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{ssha256}luYWfFJOZgxySTsJXHgIaCYww4yMpu6yest69j/wO5n5OycuHFV/GQ==";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_sha512() {
        let im_pw = "{SHA512}sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{sha512}sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_ssha512() {
        let im_pw = "{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
        let _r = Password::try_from(im_pw).expect("Failed to parse");

        let im_pw = "{ssha512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    // Can be generated with:
    // slappasswd -s password -o module-load=/usr/lib64/openldap/pw-argon2.so -h {ARGON2}

    #[test]
    fn test_password_from_openldap_pkbdf2() {
        let im_pw = "{PBKDF2}10000$IlfapjA351LuDSwYC0IQ8Q$saHqQTuYnjJN/tmAndT.8mJt.6w";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha1() {
        let im_pw = "{PBKDF2-SHA1}10000$ZBEH6B07rgQpJSikyvMU2w$TAA03a5IYkz1QlPsbJKvUsTqNV";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha256() {
        let im_pw = "{PBKDF2-SHA256}10000$henZGfPWw79Cs8ORDeVNrQ$1dTJy73v6n3bnTmTZFghxHXHLsAzKaAy8SksDfZBPIw";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha512() {
        let im_pw = "{PBKDF2-SHA512}10000$Je1Uw19Bfv5lArzZ6V3EPw$g4T/1sqBUYWl9o93MVnyQ/8zKGSkPbKaXXsT8WmysXQJhWy8MRP2JFudSL.N9RklQYgDPxPjnfum/F2f/TrppA";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    // Not supported in openssl, may need an external crate.
    #[test]
    fn test_password_from_openldap_argon2() {
        sketching::test_init();
        let im_pw = "{ARGON2}$argon2id$v=19$m=65536,t=2,p=1$IyTQMsvzB2JHDiWx8fq7Ew$VhYOA7AL0kbRXI5g2kOyyp8St1epkNj7WZyUY4pAIQQ";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(!r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ipa_nt_hash() {
        sketching::test_init();
        // Base64 no pad
        let im_pw = "ipaNTHash: iEb36u6PsRetBr3YMLdYbA";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());

        assert!(r.verify(password).expect("Failed to hash"));
        let im_pw = "ipaNTHash: pS43DjQLcUYhaNF_cd_Vhw==";
        Password::try_from(im_pw).expect("Failed to parse");
    }

    #[test]
    fn test_password_from_samba_nt_hash() {
        sketching::test_init();
        // Base64 no pad
        let im_pw = "sambaNTPassword: 8846F7EAEE8FB117AD06BDD830B7586C";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).expect("Failed to hash"));
    }

    #[test]
    fn test_password_from_crypt_md5() {
        sketching::test_init();
        let im_pw = "{crypt}$1$zaRIAsoe$7887GzjDTrst0XbDPpF5m.";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_crypt_sha256() {
        sketching::test_init();
        let im_pw = "{crypt}$5$3UzV7Sut8EHCUxlN$41V.jtMQmFAOucqI4ImFV43r.bRLjPlN.hyfoCdmGE2";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_crypt_sha512() {
        sketching::test_init();
        let im_pw = "{crypt}$6$aXn8azL8DXUyuMvj$9aJJC/KEUwygIpf2MTqjQa.f0MEXNg2cGFc62Fet8XpuDVDedM05CweAlxW6GWxnmHqp14CRf6zU7OQoE/bCu0";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");

        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_argon2id_hsm_bind() {
        sketching::test_init();

        let mut hsm: Box<dyn TpmHmacS256> = Box::new(SoftTpm::default());

        let auth_value = AuthValue::ephemeral().unwrap();

        let loadable_machine_key = hsm.root_storage_key_create(&auth_value).unwrap();
        let machine_key = hsm
            .root_storage_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_hmac_key = hsm.hmac_s256_create(&machine_key).unwrap();
        let key = hsm
            .hmac_s256_load(&machine_key, &loadable_hmac_key)
            .unwrap();

        let ctx: &mut dyn TpmHmacS256 = &mut *hsm;

        let p = CryptoPolicy::minimum();
        let c = Password::new_argon2id_hsm(&p, "password", ctx, &key).unwrap();

        assert!(matches!(
            c.verify("password"),
            Err(CryptoError::HsmContextMissing)
        ));

        // Assert it fails without the hmac
        let dup = match &c.material {
            Kdf::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => Password {
                material: Kdf::ARGON2ID {
                    m_cost: *m_cost,
                    t_cost: *t_cost,
                    p_cost: *p_cost,
                    version: *version,
                    salt: salt.clone(),
                    key: key.clone(),
                },
            },
            #[allow(clippy::unreachable)]
            _ => unreachable!(),
        };

        assert!(!dup.verify("password").unwrap());

        assert!(c.verify_ctx("password", Some((ctx, &key))).unwrap());
        assert!(!c.verify_ctx("password1", Some((ctx, &key))).unwrap());
        assert!(!c.verify_ctx("Password1", Some((ctx, &key))).unwrap());
    }
}
