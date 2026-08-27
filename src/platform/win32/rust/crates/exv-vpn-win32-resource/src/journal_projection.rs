// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Projecting the W14 durable journal into recovery obligations (W25-I).
//!
//! The WSP2 facts (native-authority-storage-facts.md §4) freeze the crash
//! semantics this projection surfaces: a torn final tail recovers to the last
//! complete record (a torn frame is NOT an admission and never enters the
//! recovery decision), and a corrupt middle record yields `Corrupt` at that
//! record's offset — never skipped, no proof past it. The projection digests
//! the recovered records into the `CleanProof::journal_root_or_projection_digest`
//! input; recomputing the same projection must produce the same digest.

use std::fmt;

use exv_vpn_resource::journal::{encode, JournalRecord};
use sha2::{Digest, Sha256};

use crate::journal_path::JournalPath;
use crate::journal_store::{RecoverOutcome, WinJournalStore};
use crate::native_error::NativeError;

/// The result of projecting the journal into durable records.
///
/// `JournalRecord` is deliberately plain (J50 codec — no derived traits), so
/// this projection provides the derived traits the codec type lacks, comparing
/// and cloning the public fields.
pub enum ProjectionOutcome {
    /// Every record decoded cleanly.
    Clean(Vec<JournalRecord>),
    /// The final frame is torn; `records` are the complete records before it
    /// (WSP2 §4: torn tail recovers to the last complete record).
    TornTail { records: Vec<JournalRecord> },
    /// A record failed validation at byte `offset`; later records are not
    /// trusted (WSP2 §4: corrupt middle reports `Corrupt`, never skips).
    Corrupt { offset: usize },
}

/// `JournalRecord` is deliberately plain (J50 codec — no derived traits), so
/// the projection carries the recovered records and provides the derived
/// traits the codec type lacks, cloning the public fields.
fn clone_records(records: &[JournalRecord]) -> Vec<JournalRecord> {
    records
        .iter()
        .map(|record| JournalRecord {
            sequence: record.sequence,
            payload: record.payload.clone(),
            previous_digest: record.previous_digest,
            digest: record.digest,
        })
        .collect()
}

fn records_eq(left: &[JournalRecord], right: &[JournalRecord]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| {
                a.sequence == b.sequence
                    && a.payload == b.payload
                    && a.previous_digest == b.previous_digest
                    && a.digest == b.digest
            })
}

impl Clone for ProjectionOutcome {
    fn clone(&self) -> Self {
        match self {
            ProjectionOutcome::Clean(records) => ProjectionOutcome::Clean(clone_records(records)),
            ProjectionOutcome::TornTail { records } => ProjectionOutcome::TornTail {
                records: clone_records(records),
            },
            ProjectionOutcome::Corrupt { offset } => ProjectionOutcome::Corrupt {
                offset: *offset,
            },
        }
    }
}

impl PartialEq for ProjectionOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ProjectionOutcome::Clean(left), ProjectionOutcome::Clean(right)) => {
                records_eq(left, right)
            }
            (
                ProjectionOutcome::TornTail { records: left },
                ProjectionOutcome::TornTail { records: right },
            ) => records_eq(left, right),
            (ProjectionOutcome::Corrupt { offset: left }, ProjectionOutcome::Corrupt { offset: right }) => {
                left == right
            }
            _ => false,
        }
    }
}

/// Compact per-record summaries for `Debug` (the codec type carries no `Debug`).
fn summarize(records: &[JournalRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            format!(
                "JournalRecord {{ sequence: {}, payload: {} bytes, digest: {:02x}.. }}",
                record.sequence,
                record.payload.len(),
                record.digest[0]
            )
        })
        .collect()
}

impl fmt::Debug for ProjectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProjectionOutcome::Clean(records) => {
                f.debug_tuple("Clean").field(&summarize(records)).finish()
            }
            ProjectionOutcome::TornTail { records } => f
                .debug_struct("TornTail")
                .field("records", &summarize(records))
                .finish(),
            ProjectionOutcome::Corrupt { offset } => f
                .debug_struct("Corrupt")
                .field("offset", offset)
                .finish(),
        }
    }
}

/// The durable-journal projection (W25-I): reads the W14 store, classifies the
/// J50 outcome, and digests the recovered records for proof binding.
pub struct JournalProjection {
    journal: JournalPath,
}

impl JournalProjection {
    /// A projection over the journal directory `journal`.
    #[must_use]
    pub fn new(journal: &JournalPath) -> Self {
        Self {
            journal: JournalPath::from_dir(journal.as_path().to_path_buf()),
        }
    }

    /// A projection consuming an owned journal path (the recovery engine's
    /// by-value seam; consumes the path instead of borrowing it).
    #[must_use]
    pub(crate) fn from_dir(journal: JournalPath) -> Self {
        Self { journal }
    }

    /// Project the journal into its recovery shape.
    ///
    /// Delegates to the committed W14 store (`WinJournalStore::open` +
    /// `recover`); the store's `RecoverOutcome` is mapped 1:1 onto
    /// [`ProjectionOutcome`] (torn tail -> last complete record, corrupt ->
    /// `Corrupt { offset }`, never skip).
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] when the journal cannot be opened or
    /// read (including an ACL-tamper `Permission` error).
    pub fn project(&self) -> Result<ProjectionOutcome, NativeError> {
        let store = WinJournalStore::open(&self.journal)?;
        Ok(match store.recover()? {
            RecoverOutcome::Clean(records) => ProjectionOutcome::Clean(records),
            RecoverOutcome::TornTail { records } => ProjectionOutcome::TornTail { records },
            RecoverOutcome::Corrupt { offset } => ProjectionOutcome::Corrupt { offset },
        })
    }

    /// The durable projection digest of `records`.
    ///
    /// SHA-256 over the concatenated canonical J50 frames (the committed
    /// `encode` codec) — the `CleanProof::journal_root_or_projection_digest`
    /// input. Recomputation over the same projection is stable.
    #[must_use]
    pub fn projection_digest(&self, records: &[JournalRecord]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for record in records {
            hasher.update(encode(record));
        }
        hasher.finalize().into()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
