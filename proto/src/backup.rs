//! Relates to backup functionality in the Server
use std::{fmt::Display, path::Path, str::FromStr};

use serde_with::DeserializeFromStr;
use sketching::tracing::warn;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, DeserializeFromStr)]
/// Compression types for backups, defaults to Gzip
pub enum BackupCompression {
    NoCompression,
    #[default]
    Gzip,
}

impl BackupCompression {
    pub fn suffix(&self) -> &'static str {
        match self {
            BackupCompression::NoCompression => "",
            BackupCompression::Gzip => ".gz",
        }
    }

    pub fn identify_file(filepath: &Path) -> Self {
        let filename = filepath.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if filename.ends_with(".gz") {
            BackupCompression::Gzip
        } else {
            BackupCompression::NoCompression
        }
    }
}

impl Display for BackupCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BackupCompression::NoCompression => write!(f, "No Compression"),
            BackupCompression::Gzip => write!(f, "Gzip"),
        }
    }
}

impl From<Option<String>> for BackupCompression {
    fn from(opt: Option<String>) -> Self {
        match opt {
            Some(s) => BackupCompression::from(s),
            None => BackupCompression::default(),
        }
    }
}

impl From<String> for BackupCompression {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "gzip" => BackupCompression::Gzip,
            "none" | "nocompression" => BackupCompression::NoCompression,
            _ => {
                warn!(
                    "Unknown compression type '{}', should be one of nocompression, gzip - defaulting to {}",
                    s,
                    BackupCompression::default()
                );
                BackupCompression::default()
            }
        }
    }
}

impl FromStr for BackupCompression {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.to_string().into())
    }
}

#[test]

fn test_backup_compression_identify() {
    let gzip_path = Path::new("/var/lib/kanidm/backups/backup-2024-01-01.tar.gz");
    let no_comp_path = Path::new("/var/lib/kanidm/backups/backup-2024-01-01.tar");

    assert_eq!(
        BackupCompression::identify_file(gzip_path),
        BackupCompression::Gzip
    );
    assert_eq!(
        BackupCompression::identify_file(no_comp_path),
        BackupCompression::NoCompression
    );

    for (input, expected) in [
        (vec!["gzip", "Gzip", "GzIp"], BackupCompression::Gzip),
        (
            vec!["none", "NoNe", "nocompression", "NoCompression"],
            BackupCompression::NoCompression,
        ),
    ] {
        for i in input {
            assert_eq!(
                BackupCompression::from_str(i).expect("Threw an error?"),
                expected
            );
        }
    }
}
