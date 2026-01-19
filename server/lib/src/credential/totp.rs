use std::convert::{TryFrom, TryInto};
use std::time::{Duration, SystemTime};

use kanidm_proto::internal::{TotpAlgo as ProtoTotpAlgo, TotpSecret as ProtoTotp};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use rand::RngExt;

use crate::be::dbvalue::{DbTotpAlgoV1, DbTotpV1};

// Update to match advice that totp hmac key should be the same
// number of bytes as the output.
const SECRET_SIZE_BYTES: usize = 32;
pub const TOTP_DEFAULT_STEP: u64 = 30;

#[derive(Debug, PartialEq, Eq)]
pub enum TotpError {
    OpenSSLError,
    HmacError,
    TimeError,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpDigits {
    Six = 1_000_000,
    Eight = 100_000_000,
}

impl TryFrom<u8> for TotpDigits {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(TotpDigits::Six),
            8 => Ok(TotpDigits::Eight),
            _ => Err(()),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<u8> for TotpDigits {
    fn into(self) -> u8 {
        match self {
            TotpDigits::Six => 6,
            TotpDigits::Eight => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgo {
    pub(crate) fn digest(self, key: &[u8], counter: u64) -> Result<Vec<u8>, TotpError> {
        let key = PKey::hmac(key).map_err(|_e| TotpError::OpenSSLError)?;
        let mut signer =
            match self {
                TotpAlgo::Sha1 => Signer::new(MessageDigest::sha1(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
                TotpAlgo::Sha256 => Signer::new(MessageDigest::sha256(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
                TotpAlgo::Sha512 => Signer::new(MessageDigest::sha512(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
            };
        signer
            .update(&counter.to_be_bytes())
            .map_err(|_e| TotpError::OpenSSLError)?;
        let hmac = signer.sign_to_vec().map_err(|_e| TotpError::OpenSSLError)?;

        let expect = match self {
            TotpAlgo::Sha1 => 20,
            TotpAlgo::Sha256 => 32,
            TotpAlgo::Sha512 => 64,
        };
        if hmac.len() != expect {
            return Err(TotpError::HmacError);
        }
        Ok(hmac)
    }
}

/// <https://tools.ietf.org/html/rfc6238> which relies on <https://tools.ietf.org/html/rfc4226>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    secret: Vec<u8>,
    pub(crate) step: u64,
    algo: TotpAlgo,
    digits: TotpDigits,
}

impl TryFrom<DbTotpV1> for Totp {
    type Error = ();

    fn try_from(value: DbTotpV1) -> Result<Self, Self::Error> {
        let algo = match value.algo {
            DbTotpAlgoV1::S1 => TotpAlgo::Sha1,
            DbTotpAlgoV1::S256 => TotpAlgo::Sha256,
            DbTotpAlgoV1::S512 => TotpAlgo::Sha512,
        };
        // Default.
        let digits = TotpDigits::try_from(value.digits.unwrap_or(6))?;

        Ok(Totp {
            secret: value.key,
            step: value.step,
            algo,
            digits,
        })
    }
}

impl TryFrom<ProtoTotp> for Totp {
    type Error = ();

    fn try_from(value: ProtoTotp) -> Result<Self, Self::Error> {
        Ok(Totp {
            secret: value.secret,
            algo: match value.algo {
                ProtoTotpAlgo::Sha1 => TotpAlgo::Sha1,
                ProtoTotpAlgo::Sha256 => TotpAlgo::Sha256,
                ProtoTotpAlgo::Sha512 => TotpAlgo::Sha512,
            },
            step: value.step,
            digits: TotpDigits::try_from(value.digits)?,
        })
    }
}

impl Totp {
    pub fn new(secret: Vec<u8>, step: u64, algo: TotpAlgo, digits: TotpDigits) -> Self {
        Totp {
            secret,
            step,
            algo,
            digits,
        }
    }

    // Create a new token with secure key and algo.
    pub fn generate_secure(step: u64) -> Self {
        let mut rng = rand::rng();
        let secret: Vec<u8> = (0..SECRET_SIZE_BYTES).map(|_| rng.random()).collect();
        let algo = TotpAlgo::Sha256;
        let digits = TotpDigits::Six;
        Totp {
            secret,
            step,
            algo,
            digits,
        }
    }

    pub(crate) fn to_dbtotpv1(&self) -> DbTotpV1 {
        DbTotpV1 {
            label: "totp".to_string(),
            key: self.secret.clone(),
            step: self.step,
            algo: match self.algo {
                TotpAlgo::Sha1 => DbTotpAlgoV1::S1,
                TotpAlgo::Sha256 => DbTotpAlgoV1::S256,
                TotpAlgo::Sha512 => DbTotpAlgoV1::S512,
            },
            digits: Some(self.digits.into()),
        }
    }

    fn digest(&self, counter: u64) -> Result<u32, TotpError> {
        let hmac = self.algo.digest(&self.secret, counter)?;
        // Now take the hmac and encode it as hotp expects.
        // https://tools.ietf.org/html/rfc4226#page-7
        let offset = hmac
            .last()
            .map(|v| (v & 0xf) as usize)
            .ok_or(TotpError::HmacError)?;

        // This is based on "dynamic truncation" where the offset into
        // the hmac is dynamic based on the last byte of the hmac output.
        // Since the array is u8, and we & with 0x0F, the value of offset
        // must be in the range 0 to 15. All hmac outputs are 20 bytes
        // or greater, so 15 + 4 == 19 as the upper bound will always
        // be within the bounds of the hmac array.
        // As a result, this is safe to slice.
        #[allow(clippy::indexing_slicing)]
        let bytes: [u8; 4] = hmac[offset..offset + 4]
            .try_into()
            .map_err(|_| TotpError::HmacError)?;

        let otp = u32::from_be_bytes(bytes);
        // Treat as a u31, this masks the first bit.
        // then modulo based on the number of digits requested.
        // * For 6 digits modulo 1_000_000
        // * For 8 digits modulo 100_000_000
        // Based on this 9 is max digits.
        Ok((otp & 0x7fff_ffff) % (self.digits as u32))
    }

    pub fn do_totp_duration_from_epoch(&self, time: &Duration) -> Result<u32, TotpError> {
        let secs = time.as_secs();
        // do the window calculation
        let counter = secs / self.step;
        self.digest(counter)
    }

    pub fn do_totp(&self, time: &SystemTime) -> Result<u32, TotpError> {
        let dur = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TotpError::TimeError)?;
        self.do_totp_duration_from_epoch(&dur)
    }

    pub fn verify(&self, chal: u32, time: Duration) -> bool {
        let secs = time.as_secs();
        let counter = secs / self.step;
        // Any error becomes a failure.
        self.digest(counter).map(|v1| v1 == chal).unwrap_or(false)
            || self
                .digest(counter - 1)
                .map(|v2| v2 == chal)
                .unwrap_or(false)
    }

    pub fn to_proto(&self, accountname: &str, issuer: &str) -> ProtoTotp {
        ProtoTotp {
            accountname: accountname.to_string(),
            issuer: issuer.to_string(),
            secret: self.secret.clone(),
            step: self.step,
            algo: match self.algo {
                TotpAlgo::Sha1 => ProtoTotpAlgo::Sha1,
                TotpAlgo::Sha256 => ProtoTotpAlgo::Sha256,
                TotpAlgo::Sha512 => ProtoTotpAlgo::Sha512,
            },
            digits: self.digits.into(),
        }
    }

    pub fn is_legacy_algo(&self) -> bool {
        matches!(&self.algo, TotpAlgo::Sha1)
    }

    pub fn downgrade_to_legacy(self) -> Self {
        Totp {
            secret: self.secret,
            step: self.step,
            algo: TotpAlgo::Sha1,
            digits: self.digits,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::credential::totp::{Totp, TotpAlgo, TotpDigits, TotpError, TOTP_DEFAULT_STEP};

    #[test]
    fn hotp_basic() {
        let otp_sha1 = Totp::new(vec![0], 30, TotpAlgo::Sha1, TotpDigits::Six);
        assert_eq!(otp_sha1.digest(0), Ok(328482));
        let otp_sha256 = Totp::new(vec![0], 30, TotpAlgo::Sha256, TotpDigits::Six);
        assert_eq!(otp_sha256.digest(0), Ok(356306));
        let otp_sha512 = Totp::new(vec![0], 30, TotpAlgo::Sha512, TotpDigits::Six);
        assert_eq!(otp_sha512.digest(0), Ok(674061));
    }

    fn do_test(
        key: &[u8],
        algo: TotpAlgo,
        secs: u64,
        step: u64,
        digits: TotpDigits,
        expect: &Result<u32, TotpError>,
    ) {
        let otp = Totp::new(key.to_vec(), step, algo, digits);
        let d = Duration::from_secs(secs);
        let r = otp.do_totp_duration_from_epoch(&d);
        debug!(
            "key: {:?}, algo: {:?}, time: {:?}, step: {:?}, expect: {:?} == {:?}",
            key, algo, secs, step, expect, r
        );
        assert_eq!(&r, expect);
    }

    #[test]
    fn totp_sha1_vectors() {
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha1,
            1585368920,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(728926),
        );
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha1,
            1585368920,
            TOTP_DEFAULT_STEP,
            TotpDigits::Eight,
            &Ok(74728926),
        );
        do_test(
            &[0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha1,
            1585369498,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(985074),
        );
    }

    #[test]
    fn totp_sha256_vectors() {
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha256,
            1585369682,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(795483),
        );
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha256,
            1585369682,
            TOTP_DEFAULT_STEP,
            TotpDigits::Eight,
            &Ok(11795483),
        );
        do_test(
            &[0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha256,
            1585369689,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(728402),
        );
    }

    #[test]
    fn totp_sha512_vectors() {
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha512,
            1585369775,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(587735),
        );
        do_test(
            &[0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha512,
            1585369775,
            TOTP_DEFAULT_STEP,
            TotpDigits::Eight,
            &Ok(14587735),
        );
        do_test(
            &[0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha512,
            1585369780,
            TOTP_DEFAULT_STEP,
            TotpDigits::Six,
            &Ok(952181),
        );
    }

    #[test]
    fn totp_allow_one_previous() {
        let key = vec![0x00, 0xaa, 0xbb, 0xcc];
        let secs = 1585369780;
        let otp = Totp::new(key, TOTP_DEFAULT_STEP, TotpAlgo::Sha512, TotpDigits::Six);
        let d = Duration::from_secs(secs);
        // Step
        assert!(otp.verify(952181, d));
        // Step - 1
        assert!(otp.verify(685469, d));
        // This is step - 2
        assert!(!otp.verify(217213, d));
        // This is step + 1
        assert!(!otp.verify(972806, d));
    }
}
