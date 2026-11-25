use std::{fmt, time::Duration};
use time::OffsetDateTime;

use crate::{be::dbvalue::DbCidV1, prelude::*};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct Cid {
    // Mental note: Derive ord always checks in order of struct fields.
    pub ts: Duration,
    pub s_uuid: Uuid,
}

impl From<DbCidV1> for Cid {
    fn from(
        DbCidV1 {
            server_id,
            timestamp,
        }: DbCidV1,
    ) -> Self {
        Cid {
            ts: timestamp,
            s_uuid: server_id,
        }
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032}-{}", self.ts.as_nanos(), self.s_uuid)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032}-{}", self.ts.as_nanos(), self.s_uuid)
    }
}

impl From<&Cid> for OffsetDateTime {
    fn from(cid: &Cid) -> Self {
        OffsetDateTime::UNIX_EPOCH + cid.ts
    }
}

impl Cid {
    pub(crate) fn new(s_uuid: Uuid, ts: Duration) -> Self {
        Cid { s_uuid, ts }
    }

    pub fn new_lamport(s_uuid: Uuid, ts: Duration, max_ts: &Duration) -> Self {
        let ts = if ts > *max_ts {
            ts
        } else {
            *max_ts + Duration::from_nanos(1)
        };
        Cid { ts, s_uuid }
    }

    /// ⚠️  - Create a new cid at timestamp zero.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_zero() -> Self {
        Self::new_count(0)
    }

    /// ⚠️  - Create a new cid with a manually defined timestamp.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_count(c: u64) -> Self {
        Cid {
            s_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
            ts: Duration::new(c, 0),
        }
    }

    pub fn sub_secs(&self, secs: u64) -> Result<Self, OperationError> {
        self.ts
            .checked_sub(Duration::from_secs(secs))
            .map(|r| Cid {
                s_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
                ts: r,
            })
            .ok_or(OperationError::InvalidReplChangeId)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::{cmp::Ordering, time::Duration};

    use crate::repl::cid::Cid;

    #[test]
    fn test_cid_ordering() {
        // Check diff ts
        let cid_a = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );
        let cid_b = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(15, 0),
        );

        assert_eq!(cid_a.cmp(&cid_a), Ordering::Equal);
        assert_eq!(cid_a.cmp(&cid_b), Ordering::Less);
        assert_eq!(cid_b.cmp(&cid_a), Ordering::Greater);

        // check same ts, d_uuid, diff s_uuid
        let cid_e = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000000"),
            Duration::new(5, 0),
        );
        let cid_f = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );

        assert_eq!(cid_e.cmp(&cid_e), Ordering::Equal);
        assert_eq!(cid_e.cmp(&cid_f), Ordering::Less);
        assert_eq!(cid_f.cmp(&cid_e), Ordering::Greater);
    }

    #[test]
    fn test_cid_lamport() {
        let s_uuid = uuid!("00000000-0000-0000-0000-000000000001");

        let ts5 = Duration::new(5, 0);
        let ts10 = Duration::new(10, 0);
        let ts15 = Duration::new(15, 0);

        let cid_z = Cid::new_zero();

        let cid_a = Cid::new_lamport(s_uuid, ts5, &ts5);
        assert_eq!(cid_a.cmp(&cid_z), Ordering::Greater);
        let cid_b = Cid::new_lamport(s_uuid, ts15, &ts10);
        assert_eq!(cid_b.cmp(&cid_a), Ordering::Greater);
        // Even with an older ts, we should still step forward.
        let cid_c = Cid::new_lamport(s_uuid, ts10, &ts15);
        assert_eq!(cid_c.cmp(&cid_b), Ordering::Greater);
    }
}
