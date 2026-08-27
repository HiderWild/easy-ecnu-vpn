// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Portable append-only journal codec (Architecture spec §7.3).
//!
//! A journal is a versioned, append-only, length-delimited record log with a monotonic
//! sequence, a previous-record digest chain, and a per-record payload digest. Consumers must
//! never treat a record as durable until its full frame is present AND its digest verifies.

use sha2::{Digest, Sha256};

/// On-disk format version for journal frames.
pub const JOURNAL_VERSION: u8 = 1;

/// Maximum accepted payload length per record (1 MiB).
pub const MAX_PAYLOAD_LEN: u32 = 1 << 20;

/// A single durable journal record.
pub struct JournalRecord {
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub previous_digest: [u8; 32],
    pub digest: [u8; 32],
}

impl JournalRecord {
    pub fn new(sequence: u64, previous_digest: [u8; 32], payload: Vec<u8>) -> Self {
        let digest = record_digest(sequence, &previous_digest, &payload);
        Self {
            sequence,
            payload,
            previous_digest,
            digest,
        }
    }
}

/// SHA-256 over `version_byte || sequence_be8 || payload_len_be4 || previous_digest32 || payload`.
pub fn record_digest(sequence: u64, previous_digest: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([JOURNAL_VERSION]);
    hasher.update(sequence.to_be_bytes());
    hasher.update((payload.len() as u32).to_be_bytes());
    hasher.update(previous_digest);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Encode a record into its canonical frame.
///
/// Frame layout:
/// ```text
/// [0]            version (1 byte)           = JOURNAL_VERSION
/// [1..9]         sequence (8 bytes BE u64)
/// [9..13]        payload_len (4 bytes BE u32)
/// [13..45]       previous_digest (32 bytes)
/// [45..45+len]   payload
/// [45+len..]     digest (32 bytes)
/// ```
pub fn encode(record: &JournalRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(45 + record.payload.len() + 32);
    out.push(JOURNAL_VERSION);
    out.extend_from_slice(&record.sequence.to_be_bytes());
    out.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&record.previous_digest);
    out.extend_from_slice(&record.payload);
    out.extend_from_slice(&record.digest);
    out
}

/// Result of decoding a byte buffer into journal records.
pub enum DecodeOutcome {
    /// Every frame decoded cleanly.
    Clean(Vec<JournalRecord>),
    /// The buffer ends inside a final record's frame (partial header or truncated digest).
    /// `records` are the complete, durable records that precede the torn final record; the torn
    /// record itself is excluded.
    TornTail {
        records: Vec<JournalRecord>,
    },
    /// A record failed validation (bad version, oversized payload, incomplete non-final payload,
    /// or digest mismatch). `recovered` are the complete valid records before the corrupt record;
    /// `offset` is the byte offset of the corrupt record.
    Corrupt {
        recovered: Vec<JournalRecord>,
        offset: usize,
    },
}

/// Decode a byte buffer into journal records.
///
/// A record is durable only when its full frame is present AND its digest verifies. A buffer that
/// ends inside a final record's frame (partial header or truncated digest) recovers the complete
/// records before it as a torn tail. Any inconsistency in a non-final record (including an
/// incomplete payload that is not the final thing) is corruption: we never skip forward.
pub fn decode(bytes: &[u8]) -> DecodeOutcome {
    let mut records: Vec<JournalRecord> = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let remaining = bytes.len() - offset;

        // Step 1: fewer than 45 bytes remain — this is an incomplete final header (torn tail).
        if remaining < 45 {
            return DecodeOutcome::TornTail { records };
        }

        // Step 2: read and validate the header.
        let version = bytes[offset];
        let sequence = u64::from_be_bytes(bytes[offset + 1..offset + 9].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[offset + 9..offset + 13].try_into().unwrap());
        let previous_digest: [u8; 32] =
            bytes[offset + 13..offset + 45].try_into().unwrap();

        if version != JOURNAL_VERSION {
            return DecodeOutcome::Corrupt {
                recovered: records,
                offset,
            };
        }
        if payload_len > MAX_PAYLOAD_LEN {
            return DecodeOutcome::Corrupt {
                recovered: records,
                offset,
            };
        }

        let payload_len = payload_len as usize;
        let remaining_after_header = remaining - 45;

        // Step 3: payload incomplete. A non-final incomplete record is corruption, never a torn
        // tail (test 10 pins this): a decoder cannot distinguish an incomplete payload that ends
        // the buffer from one followed by garbage, so the safety principle wins — never skip.
        if payload_len > remaining_after_header {
            return DecodeOutcome::Corrupt {
                recovered: records,
                offset,
            };
        }

        // Step 4: payload fully present. Verify the digest.
        let payload_end = offset + 45 + payload_len;
        let remaining_after_payload = bytes.len() - payload_end;

        // Payload complete but the 32-byte digest is truncated: torn final tail.
        if remaining_after_payload < 32 {
            return DecodeOutcome::TornTail { records };
        }

        let payload = &bytes[offset + 45..payload_end];
        let stored_digest: [u8; 32] =
            bytes[payload_end..payload_end + 32].try_into().unwrap();
        let computed = record_digest(sequence, &previous_digest, payload);
        if computed != stored_digest {
            return DecodeOutcome::Corrupt {
                recovered: records,
                offset,
            };
        }

        // Step 5: record is valid.
        records.push(JournalRecord {
            sequence,
            payload: payload.to_vec(),
            previous_digest,
            digest: stored_digest,
        });
        offset = payload_end + 32;
    }

    DecodeOutcome::Clean(records)
}

/// Error reported by [`verify_chain`].
pub enum ChainError {
    /// `records[index].sequence` does not equal the expected monotonic value.
    SequenceGap { index: usize, expected: u64, found: u64 },
    /// `records[index]` has a wrong previous_digest link or an internally inconsistent digest.
    DigestMismatch { index: usize },
}

/// Verify the digest chain and monotonic sequence across a slice of records.
///
/// The first record must use an all-zero previous_digest, sequence 0, and a self-consistent
/// digest. Each subsequent record `i` must have sequence `i` and a previous_digest equal to the
/// prior record's digest, plus a self-consistent digest. Empty input is valid.
pub fn verify_chain(records: &[JournalRecord]) -> Result<(), ChainError> {
    if records.is_empty() {
        return Ok(());
    }

    let zero = [0u8; 32];
    if records[0].previous_digest != zero
        || records[0].digest != record_digest(0, &zero, &records[0].payload)
    {
        return Err(ChainError::DigestMismatch { index: 0 });
    }

    for i in 1..records.len() {
        let expected = i as u64;
        if records[i].sequence != expected {
            return Err(ChainError::SequenceGap {
                index: i,
                expected,
                found: records[i].sequence,
            });
        }
        if records[i].previous_digest != records[i - 1].digest
            || records[i].digest
                != record_digest(
                    records[i].sequence,
                    &records[i].previous_digest,
                    &records[i].payload,
                )
        {
            return Err(ChainError::DigestMismatch { index: i });
        }
    }

    Ok(())
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。