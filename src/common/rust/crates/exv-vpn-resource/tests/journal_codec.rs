// RED tests for the journal codec (Architecture spec §7.3, vpn-rust-native-runtime-mvp-common-architecture.md).
// This is a PURE, deterministic codec test: no I/O, no filesystem, no sleep, no randomness.
// The production module `exv_vpn_resource::journal` does not exist yet; J50-I implements it.
// Until then this file FAILS TO COMPILE (unresolved names) — that is the intended RED.

use exv_vpn_resource::journal::{
    ChainError, DecodeOutcome, JournalRecord, JOURNAL_VERSION, decode, encode, record_digest,
    verify_chain,
};

/// Encode a record with a known payload, decode it back, and require a clean single-record
/// round trip whose digest matches the recomputed digest. Kills: "encode drops the digest /
/// decode ignores the digest field".
#[test]
fn round_trip_single_record_clean() {
    let payload = vec![0x42u8; 64];
    let prev = [0x12u8; 32];
    let rec = JournalRecord::new(0, prev, payload.clone());
    assert_eq!(rec.digest, record_digest(0, &prev, &payload));

    let bytes = encode(&rec);
    assert!(
        matches!(&decode(&bytes), DecodeOutcome::Clean(records)
            if records.len() == 1
                && records[0].sequence == rec.sequence
                && records[0].payload == rec.payload
                && records[0].previous_digest == rec.previous_digest
                && records[0].digest == rec.digest),
        "expected a single clean record matching the original (digest preserved)"
    );
}

/// Build a 3-record chain, encode+concat, and require a clean decode of 3 records in sequence
/// 0,1,2. Kills: "decode returns records out of order / wrong sequence decode".
#[test]
fn round_trip_chain_clean_and_monotonic() {
    let mut all = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..3u64 {
        let rec = JournalRecord::new(i, prev, vec![i as u8; 16]);
        prev = rec.digest;
        all.extend_from_slice(&encode(&rec));
    }
    assert!(
        matches!(&decode(&all), DecodeOutcome::Clean(records)
            if records.len() == 3
                && records[0].sequence == 0
                && records[1].sequence == 1
                && records[2].sequence == 2),
        "expected a clean decode of 3 chained records in order 0,1,2"
    );
}

/// A sequence-0 record with an all-zero previous_digest must decode clean; verify_chain must
/// reject a first record whose previous_digest is non-zero. Kills: "first record previous_digest
/// is not validated against zero".
#[test]
fn first_record_uses_zero_previous_digest() {
    let rec = JournalRecord::new(0, [0u8; 32], vec![0x01, 0x02, 0x03]);
    let bytes = encode(&rec);
    assert!(
        matches!(&decode(&bytes), DecodeOutcome::Clean(records) if records.len() == 1),
        "sequence-0 record with zero previous_digest must decode clean"
    );

    let bad = JournalRecord::new(0, [7u8; 32], vec![0x01, 0x02, 0x03]);
    let res = verify_chain(&[bad]);
    assert!(
        matches!(res, Err(ChainError::DigestMismatch { index: 0 })),
        "first record with non-zero previous_digest must be a DigestMismatch at index 0"
    );
}

/// A chain with sequences 0,1,3 (a jump) must be rejected as a SequenceGap at index 2.
/// Kills: "sequence monotonicity not checked".
#[test]
fn verify_chain_rejects_sequence_gap() {
    let mut records = Vec::new();
    let mut prev = [0u8; 32];
    for (i, seq) in [0u64, 1, 3].iter().enumerate() {
        let rec = JournalRecord::new(*seq, prev, vec![i as u8; 8]);
        prev = rec.digest;
        records.push(rec);
    }
    let res = verify_chain(&records);
    assert!(
        matches!(
            res,
            Err(ChainError::SequenceGap { index: 2, expected: 2, found: 3 })
        ),
        "a sequence jump 0,1,3 must be reported as SequenceGap at index 2 (expected 2, found 3)"
    );
}

/// Truncating the final record's payload must decode as TornTail recovering ONLY the complete
/// records before the torn tail (the torn record itself is not durable and is excluded — §7.3
/// "recover to the last COMPLETE durable record"). Kills: "truncated final record is treated as
/// Clean or is included as a durable record".
#[test]
fn torn_final_payload_recovers_to_last_complete() {
    let r0 = JournalRecord::new(0, [0u8; 32], vec![0xAAu8; 32]);
    let r1 = JournalRecord::new(1, r0.digest, vec![0xBBu8; 32]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode(&r0));
    bytes.extend_from_slice(&encode(&r1));
    // drop the last 10 bytes (part of r1's payload frame) => r1 becomes a torn, non-durable tail
    bytes.truncate(bytes.len() - 10);

    assert!(
        matches!(&decode(&bytes), DecodeOutcome::TornTail { records }
            if records.len() == 1
                && records[0].sequence == 0),
        "truncated final payload must decode as TornTail recovering only the complete records (r0), never the torn r1"
    );
}

/// Keeping only 3 bytes (mid-header) of a record must decode as TornTail with no records.
/// Kills: "partial header is not detected as torn".
#[test]
fn torn_final_header_only() {
    let rec = JournalRecord::new(0, [0u8; 32], vec![0xABu8; 16]);
    let bytes = encode(&rec);
    assert!(
        matches!(&decode(&bytes[..3]), DecodeOutcome::TornTail { records } if records.is_empty()),
        "a partial header (3 bytes) must decode as TornTail with no records"
    );
}

/// A payload byte flip in the middle record must be Corrupt (recovering only record0), never
/// skipping to record2. Kills: "corrupt record is skipped and later records returned".
#[test]
fn middle_payload_corruption_is_corrupt_not_torn() {
    let r0 = JournalRecord::new(0, [0u8; 32], vec![0xAAu8; 32]);
    let r1 = JournalRecord::new(1, r0.digest, vec![0xBBu8; 32]);
    let r2 = JournalRecord::new(2, r1.digest, vec![0xCCu8; 32]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode(&r0));
    bytes.extend_from_slice(&encode(&r1));
    bytes.extend_from_slice(&encode(&r2));

    let r1_offset = encode(&r0).len();
    // flip a byte in the middle of r1's payload (NOT its digest)
    let payload_mid = r1_offset + 45 + 16;
    bytes[payload_mid] ^= 0xFF;

    assert!(
        matches!(&decode(&bytes), DecodeOutcome::Corrupt { recovered, offset }
            if recovered.len() == 1
                && recovered[0].sequence == 0
                && *offset == r1_offset),
        "a payload flip in the middle record must be Corrupt recovering only record0, not skip to r2"
    );
}

/// A digest byte flip must be detected as Corrupt (digest must be recomputed, not trusted).
/// Kills: "decode trusts the stored digest without recomputing".
#[test]
fn middle_digest_byte_flip_is_corrupt() {
    let r0 = JournalRecord::new(0, [0u8; 32], vec![0xAAu8; 32]);
    let r1 = JournalRecord::new(1, r0.digest, vec![0xBBu8; 32]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode(&r0));
    bytes.extend_from_slice(&encode(&r1));

    // flip a byte in r1's digest field (last 32 bytes of r1's frame)
    let digest_flip = bytes.len() - 1;
    bytes[digest_flip] ^= 0xFF;

    assert!(
        matches!(&decode(&bytes), DecodeOutcome::Corrupt { recovered, .. }
            if recovered.len() == 1 && recovered[0].sequence == 0),
        "a digest byte flip must be detected as Corrupt (digest must be recomputed)"
    );
}

/// Changing the version byte must decode as Corrupt with no recovered records.
/// Kills: "version field not validated".
#[test]
fn version_mismatch_is_corrupt() {
    let rec = JournalRecord::new(0, [0u8; 32], vec![0xCDu8; 16]);
    let mut bytes = encode(&rec);
    bytes[0] = JOURNAL_VERSION.wrapping_add(1);

    assert!(
        matches!(&decode(&bytes), DecodeOutcome::Corrupt { recovered, .. } if recovered.is_empty()),
        "a version byte mismatch must decode as Corrupt with no recovered records"
    );
}

/// An incomplete record that is NOT the final thing in the buffer (followed by bytes that
/// cannot start a next record) must be Corrupt, never TornTail. Kills: "any incomplete record is
/// misclassified as TornTail".
#[test]
fn incomplete_record_followed_by_bytes_is_corrupt() {
    let rec = JournalRecord::new(0, [0u8; 32], vec![0xCCu8; 100]);
    let mut bytes = encode(&rec);
    // header (45 bytes) + only 10 payload bytes => the declared 100-byte payload is incomplete
    bytes.truncate(45 + 10);
    // append bytes that cannot start a valid next record (version byte != JOURNAL_VERSION)
    bytes.extend_from_slice(&[0xABu8; 16]);

    let outcome = decode(&bytes);
    assert!(
        matches!(&outcome, DecodeOutcome::Corrupt { recovered, .. } if recovered.is_empty()),
        "an incomplete record followed by non-record bytes must be Corrupt"
    );
    assert!(
        !matches!(&outcome, DecodeOutcome::TornTail { .. }),
        "a non-final incomplete record must not be classified as TornTail"
    );
}