//! This module contains cryptographic setup code, a long with what policy
//! and ciphers we accept.

use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslSessionCacheMode, SslVerifyMode};
use openssl::x509::{
    extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    },
    X509NameBuilder, X509ReqBuilder, X509,
};
use openssl::{asn1, bn, hash, pkey};
use sketching::*;

use crate::config::TlsConfiguration;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

const CA_VALID_DAYS: u32 = 30;
const CERT_VALID_DAYS: u32 = 5;

// Basing minimums off https://www.keylength.com setting "year" to 2030 - tested as at 2023-09-25
//
// |Method           |Date     |Symmetric| FM      |DL Key| DL Group|Elliptic Curve|Hash|
// |   ---           |   ---   |   ---   |   ---   | ---  |   ---   |  ---         | ---|
// |Lenstra / Verheul|2030     |  93     |2493^2016|165   | 2493    |  176         | 186|
// |Lenstra Updated  |2030     |  88     |1698^2063|176   | 1698    |  176         | 176|
// |ECRYPT           |2029-2068|  256    |15360    |512   | 15360   |  512         | 512|
// |NIST             |2019-2030|  112    |2048     |224   | 2048    |  224         | 224|
// |ANSSI            |> 2030   |  128    |3072     |200   | 3072    |  256         | 256|
// |NSA              |-        |  256    |3072     |-     | -       |  384         | 384|
// |RFC3766          |-        |  -      |   -     | -    |   -     |   -          |  - |
// |BSI              |-        |  -      |   -     | -    |   -     |   -          |  - |
// DL - Discrete Logarithm
// FM - Factoring Modulus

const RSA_MIN_KEY_SIZE_BITS: u64 = 2048;
const EC_MIN_KEY_SIZE_BITS: u64 = 224;

/// returns a signing function that meets a sensible minimum
fn get_signing_func() -> hash::MessageDigest {
    hash::MessageDigest::sha256()
}

/// Ensure we're enforcing safe minimums for TLS keys
pub fn check_privkey_minimums(privkey: &PKeyRef<Private>) -> Result<(), String> {
    if let Ok(key) = privkey.rsa() {
        if key.size() < (RSA_MIN_KEY_SIZE_BITS / 8) as u32 {
            Err(format!(
                "TLS RSA key is less than {} bits!",
                RSA_MIN_KEY_SIZE_BITS
            ))
        } else {
            debug!(
                "The RSA private key size is: {} bits, that's OK!",
                key.size() * 8
            );
            Ok(())
        }
    } else if let Ok(key) = privkey.ec_key() {
        // allowing this to panic because ... it's an i32 and hopefully we don't have negative bit lengths?
        #[allow(clippy::panic)]
        let key_bits: u64 = key.private_key().num_bits().try_into().unwrap_or_else(|_| {
            panic!(
                "Failed to convert EC bitlength {} to u64",
                key.private_key().num_bits()
            )
        });

        if key_bits < EC_MIN_KEY_SIZE_BITS {
            Err(format!(
                "TLS EC key is less than {} bits! Got: {}",
                EC_MIN_KEY_SIZE_BITS, key_bits
            ))
        } else {
            #[cfg(any(test, debug_assertions))]
            println!("The EC private key size is: {} bits, that's OK!", key_bits);
            debug!("The EC private key size is: {} bits, that's OK!", key_bits);
            Ok(())
        }
    } else {
        error!("TLS key is not RSA or EC, cannot check minimums!");
        Ok(())
    }
}

/// From the server configuration, generate an OpenSSL acceptor that we can use
/// to build our sockets for HTTPS/LDAPS.
pub fn setup_tls(
    tls_config: &Option<TlsConfiguration>,
) -> Result<Option<SslAcceptor>, std::io::Error> {
    let Some(tls_param) = tls_config.as_ref() else {
        return Ok(None);
    };

    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    tls_builder
        .set_certificate_chain_file(tls_param.chain.clone())
        .map_err(|err| {
            std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
        })?;

    tls_builder
        .set_private_key_file(tls_param.key.clone(), SslFiletype::PEM)
        .map_err(|err| {
            std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
        })?;

    tls_builder.check_private_key().map_err(|err| {
        std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
    })?;

    // If configured, setup TLS client authentication.
    if let Some(client_ca) = tls_param.client_ca.as_ref() {
        info!("Loading client certificates from {}", client_ca.display());

        let verify = SslVerifyMode::PEER;
        // In future we may add a "require mTLS option" which would necessitate this.
        // verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        tls_builder.set_verify(verify);

        // When client certs are available, we disable the TLS session cache.
        // This is so that when the smartcard is *removed* on the client, it forces
        // the client session to immediately expire.
        //
        // https://stackoverflow.com/questions/12393711/session-disconnect-the-client-after-smart-card-is-removed
        //
        // Alternately, on logout we need to trigger https://docs.rs/openssl/latest/openssl/ssl/struct.Ssl.html#method.set_ssl_context
        // with https://docs.rs/openssl/latest/openssl/ssl/struct.Ssl.html#method.ssl_context +
        // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextRef.html#method.remove_session
        //
        // Or we lower session time outs etc.
        tls_builder.set_session_cache_mode(SslSessionCacheMode::OFF);

        let read_dir = fs::read_dir(client_ca).map_err(|err| {
            std::io::Error::other(format!(
                "Failed to create TLS listener while loading client ca from {}: {:?}",
                client_ca.display(),
                err
            ))
        })?;

        for cert_dir_ent in read_dir.filter_map(|item| item.ok()).filter(|item| {
            item.file_name()
                .to_str()
                // Hashed certs end in .0
                // Hashed crls are .r0
                .map(|fname| fname.ends_with(".0"))
                .unwrap_or_default()
        }) {
            let mut cert_pem = String::new();
            fs::File::open(cert_dir_ent.path())
                .and_then(|mut file| file.read_to_string(&mut cert_pem))
                .map_err(|err| {
                    std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
                })?;

            let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|err| {
                std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
            })?;

            let cert_store = tls_builder.cert_store_mut();
            cert_store.add_cert(cert.clone()).map_err(|err| {
                std::io::Error::other(format!(
                    "Failed to load cert store while creating TLS listener: {:?}",
                    err
                ))
            })?;
            // This tells the client what CA's they should use. It DOES NOT
            // verify them. That's the job of the cert store above!
            tls_builder.add_client_ca(&cert).map_err(|err| {
                std::io::Error::other(format!("Failed to create TLS listener: {:?}", err))
            })?;
        }

        // TODO: Build our own CRL map HERE!

        // Allow dumping client cert chains for dev debugging
        // In the case this is status=false, should we be dumping these anyway?
        if enabled!(tracing::Level::TRACE) {
            tls_builder.set_verify_callback(verify, |status, x509store| {
                if let Some(current_cert) = x509store.current_cert() {
                    let cert_text_bytes = current_cert.to_text().unwrap_or_default();
                    let cert_text = String::from_utf8_lossy(cert_text_bytes.as_slice());
                    tracing::warn!(client_cert = %cert_text);
                };

                if let Some(chain) = x509store.chain() {
                    for cert in chain.iter() {
                        let cert_text_bytes = cert.to_text().unwrap_or_default();
                        let cert_text = String::from_utf8_lossy(cert_text_bytes.as_slice());
                        tracing::warn!(chain_cert = %cert_text);
                    }
                }

                status
            });
        }

        // End tls_client setup
    }

    let tls_acceptor = tls_builder.build();

    // let's enforce some TLS minimums!
    let privkey = tls_acceptor.context().private_key().ok_or_else(|| {
        std::io::Error::other("Failed to access tls_acceptor private key".to_string())
    })?;

    check_privkey_minimums(privkey).map_err(|err| {
        std::io::Error::other(format!("Private key minimums were not met: {:?}", err))
    })?;

    Ok(Some(tls_acceptor))
}

fn get_ec_group() -> Result<EcGroup, ErrorStack> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
}

#[derive(Debug)]
pub(crate) struct CaHandle {
    key: pkey::PKey<pkey::Private>,
    cert: X509,
}

pub(crate) fn write_ca(
    key_ar: impl AsRef<Path>,
    cert_ar: impl AsRef<Path>,
    handle: &CaHandle,
) -> Result<(), ()> {
    let key_path: &Path = key_ar.as_ref();
    let cert_path: &Path = cert_ar.as_ref();

    let key_pem = handle.key.private_key_to_pem_pkcs8().map_err(|e| {
        error!(err = ?e, "Failed to convert key to PEM");
    })?;

    let cert_pem = handle.cert.to_pem().map_err(|e| {
        error!(err = ?e, "Failed to convert cert to PEM");
    })?;

    fs::File::create(key_path)
        .and_then(|mut file| file.write_all(&key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", key_path);
        })?;

    fs::File::create(cert_path)
        .and_then(|mut file| file.write_all(&cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", cert_path);
        })
}

#[derive(Debug)]
pub enum KeyType {
    #[allow(dead_code)]
    Rsa,
    Ec,
}
impl Default for KeyType {
    fn default() -> Self {
        Self::Ec
    }
}

#[derive(Debug)]
pub struct CAConfig {
    pub key_type: KeyType,
    pub key_bits: u64,
    pub skip_enforce_minimums: bool,
}

impl Default for CAConfig {
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        Self::new(KeyType::Ec, 256, false)
            .expect("Somehow the defaults failed to pass validation while building a CA Config?")
    }
}

impl CAConfig {
    fn new(key_type: KeyType, key_bits: u64, skip_enforce_minimums: bool) -> Result<Self, String> {
        let res = Self {
            key_type,
            key_bits,
            skip_enforce_minimums,
        };
        if !skip_enforce_minimums {
            res.enforce_minimums()?;
        };
        Ok(res)
    }

    /// Make sure we're meeting the minimum spec for key length etc
    fn enforce_minimums(&self) -> Result<(), String> {
        match self.key_type {
            KeyType::Rsa => {
                trace!(
                    "Generating CA Config for RSA Key with {} bits",
                    self.key_bits
                );
                if self.key_bits < RSA_MIN_KEY_SIZE_BITS {
                    return Err(format!(
                        "RSA key size must be at least {} bits",
                        RSA_MIN_KEY_SIZE_BITS
                    ));
                }
            }
            KeyType::Ec => {
                trace!("Generating CA Config for EcKey with {} bits", self.key_bits);
                if self.key_bits < EC_MIN_KEY_SIZE_BITS {
                    return Err(format!(
                        "EC key size must be at least {} bits",
                        EC_MIN_KEY_SIZE_BITS
                    ));
                }
            }
        };
        Ok(())
    }
}

pub(crate) fn gen_private_key(
    key_type: &KeyType,
    key_bits: Option<u64>,
) -> Result<pkey::PKey<pkey::Private>, ErrorStack> {
    match key_type {
        KeyType::Rsa => {
            let key_bits = key_bits.unwrap_or(RSA_MIN_KEY_SIZE_BITS);
            let rsa = Rsa::generate(key_bits as u32)?;
            pkey::PKey::from_rsa(rsa)
        }
        KeyType::Ec => {
            // TODO: take key bitlength and use it for the curve group, somehow?
            let ecgroup = get_ec_group()?;
            let eckey = EcKey::generate(&ecgroup)?;
            pkey::PKey::from_ec_key(eckey)
        }
    }
}

/// build up a CA certificate and key.
pub(crate) fn build_ca(ca_config: Option<CAConfig>) -> Result<CaHandle, ErrorStack> {
    let ca_config = ca_config.unwrap_or_default();

    let ca_key = gen_private_key(&ca_config.key_type, Some(ca_config.key_bits))?;

    if !ca_config.skip_enforce_minimums {
        check_privkey_minimums(&ca_key).map_err(|err| {
            admin_error!("failed to build_ca due to privkey minimums {}", err);
            #[cfg(any(test, debug_assertions))]
            println!("failed to build_ca due to privkey minimums: {}", err);
            ErrorStack::get() // this probably should be a real errorstack but... how?
        })?;
    }
    let mut x509_name = X509NameBuilder::new()?;

    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Kanidm")?;
    x509_name.append_entry_by_text("CN", "Kanidm Generated CA")?;
    x509_name.append_entry_by_text("OU", "Development and Evaluation - NOT FOR PRODUCTION")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;

    let serial_number = bn::BigNum::from_u32(1).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(CA_VALID_DAYS)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.set_pubkey(&ca_key)?;

    cert_builder.sign(&ca_key, get_signing_func())?;
    let ca_cert = cert_builder.build();

    Ok(CaHandle {
        key: ca_key,
        cert: ca_cert,
    })
}

pub(crate) fn load_ca(
    ca_key_ar: impl AsRef<Path>,
    ca_cert_ar: impl AsRef<Path>,
) -> Result<CaHandle, ()> {
    let ca_key_path: &Path = ca_key_ar.as_ref();
    let ca_cert_path: &Path = ca_cert_ar.as_ref();

    let mut ca_key_pem = vec![];
    fs::File::open(ca_key_path)
        .and_then(|mut file| file.read_to_end(&mut ca_key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to read {:?}", ca_key_path);
        })?;

    let mut ca_cert_pem = vec![];
    fs::File::open(ca_cert_path)
        .and_then(|mut file| file.read_to_end(&mut ca_cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to read {:?}", ca_cert_path);
        })?;

    let ca_key = pkey::PKey::private_key_from_pem(&ca_key_pem).map_err(|e| {
        error!(err = ?e, "Failed to convert PEM to key");
    })?;

    check_privkey_minimums(&ca_key).map_err(|err| {
        #[cfg(any(test, debug_assertions))]
        println!("{:?}", err);
        admin_error!("{}", err);
    })?;

    let ca_cert = X509::from_pem(&ca_cert_pem).map_err(|e| {
        error!(err = ?e, "Failed to convert PEM to cert");
    })?;

    Ok(CaHandle {
        key: ca_key,
        cert: ca_cert,
    })
}

pub(crate) struct CertHandle {
    key: pkey::PKey<pkey::Private>,
    cert: X509,
    chain: Vec<X509>,
}

pub(crate) fn write_cert(
    key_ar: impl AsRef<Path>,
    chain_ar: impl AsRef<Path>,
    cert_ar: impl AsRef<Path>,
    handle: &CertHandle,
) -> Result<(), ()> {
    let key_path: &Path = key_ar.as_ref();
    let chain_path: &Path = chain_ar.as_ref();
    let cert_path: &Path = cert_ar.as_ref();

    let key_pem = handle.key.private_key_to_pem_pkcs8().map_err(|e| {
        error!(err = ?e, "Failed to convert key to PEM");
    })?;

    let cert_pem = handle.cert.to_pem().map_err(|e| {
        error!(err = ?e, "Failed to convert cert to PEM");
    })?;

    let mut chain_pem = cert_pem.clone();

    // Build the chain PEM.
    for ca_cert in &handle.chain {
        match ca_cert.to_pem() {
            Ok(c) => {
                chain_pem.extend_from_slice(&c);
            }
            Err(e) => {
                error!(err = ?e, "Failed to convert cert to PEM");
                return Err(());
            }
        }
    }

    fs::File::create(key_path)
        .and_then(|mut file| file.write_all(&key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", key_path);
        })?;

    fs::File::create(chain_path)
        .and_then(|mut file| file.write_all(&chain_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", chain_path);
        })?;

    fs::File::create(cert_path)
        .and_then(|mut file| file.write_all(&cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", cert_path);
        })
}

pub(crate) fn build_cert(
    domain_name: &str,
    ca_handle: &CaHandle,
    key_type: Option<KeyType>,
    key_bits: Option<u64>,
) -> Result<CertHandle, ErrorStack> {
    let key_type = key_type.unwrap_or_default();
    let int_key = gen_private_key(&key_type, key_bits)?;

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&int_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Kanidm")?;
    x509_name.append_entry_by_text("CN", domain_name)?;
    // Requirement of packed attestation.
    x509_name.append_entry_by_text("OU", "Development and Evaluation - NOT FOR PRODUCTION")?;
    let x509_name = x509_name.build();

    req_builder.set_subject_name(&x509_name)?;
    req_builder.sign(&int_key, get_signing_func())?;
    let req = req_builder.build();
    // ==

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;
    let serial_number = bn::BigNum::from_u32(2).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_pubkey(&int_key)?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_handle.cert.subject_name())?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(CERT_VALID_DAYS)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    cert_builder.append_extension(
        ExtendedKeyUsage::new()
            // .critical()
            .server_auth()
            .build()?,
    )?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(domain_name)
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(&ca_handle.key, get_signing_func())?;
    let int_cert = cert_builder.build();

    Ok(CertHandle {
        key: int_key,
        cert: int_cert,
        chain: vec![ca_handle.cert.clone()],
    })
}

#[test]
// might as well test my logic
fn test_enforced_minimums() {
    let good_ca_configs = vec![
        // test rsa 4096 (ok)
        (KeyType::Rsa, 4096, false),
        // test rsa 2048 (ok)
        (KeyType::Rsa, 2048, false),
        // test ec 256 (ok)
        (KeyType::Ec, 256, false),
    ];
    good_ca_configs.into_iter().for_each(|config| {
        dbg!(&config);
        assert!(CAConfig::new(config.0, config.1, config.2).is_ok());
    });
    let bad_ca_configs = vec![
        // test rsa 1024 (no)
        (KeyType::Rsa, 1024, false),
        // test ec 128 (no)
        (KeyType::Ec, 128, false),
    ];
    bad_ca_configs.into_iter().for_each(|config| {
        dbg!(&config);
        assert!(CAConfig::new(config.0, config.1, config.2).is_err());
    });
}

#[test]
fn test_ca_loader() {
    let ca_key_tempfile = tempfile::NamedTempFile::new().unwrap();
    let ca_cert_tempfile = tempfile::NamedTempFile::new().unwrap();
    // let's test the defaults first

    let ca_config = CAConfig::default();
    if let Ok(ca) = build_ca(Some(ca_config)) {
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        assert!(load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path()).is_ok());
    };

    let good_ca_configs = vec![
        // test rsa 4096 (ok)
        (KeyType::Rsa, 4096, false),
        // test rsa 2048 (ok)
        (KeyType::Rsa, 2048, false),
        // test ec 256 (ok)
        (KeyType::Ec, 256, false),
    ];
    good_ca_configs.into_iter().for_each(|config| {
        println!("testing good config {:?}", config);
        let ca_config = CAConfig::new(config.0, config.1, config.2).unwrap();
        let ca = build_ca(Some(ca_config)).unwrap();
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        let ca_result = load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path());
        println!("result: {:?}", ca_result);
        assert!(ca_result.is_ok());
    });
    let bad_ca_configs = vec![
        // test rsa 1024 (bad)
        (KeyType::Rsa, 1024, true),
    ];
    bad_ca_configs.into_iter().for_each(|config| {
        println!(
            "\ntesting bad config keytype: {:?} key size: {}, skip_enforce_minimums: {}",
            config.0, config.1, config.2
        );
        let ca_config = CAConfig::new(config.0, config.1, config.2).unwrap();
        let ca = build_ca(Some(ca_config)).unwrap();
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        let ca_result = load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path());
        println!("result: {:?}", ca_result);
        assert!(ca_result.is_err());
    });
}
