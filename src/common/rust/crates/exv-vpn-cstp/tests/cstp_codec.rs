// EXV P40-T: bounded CSTP frame codec integration tests for exv-vpn-cstp.
//
// These tests define the exact public API that P40-I must implement in
// `exv_vpn_cstp::codec`. They are expected to be RED (compile error) until P40-I
// implements that codec. The codec decodes/encodes CSTP frames from a byte stream
// with a bounded header/MTU, returning a typed `CodecError` (CSTP-only, no DTLS, no UDP).
//
// Contract (RNRM-005/006/014, TG-04):
//   * The codec is a stateful streaming decoder: bytes are fed in, complete frames
//     come out one at a time; a partial frame never yields a clean finish.
//   * A bounded header (3 bytes) precedes every frame; a declared payload length above
//     the negotiated MTU is rejected BEFORE any allocation of that size.
//   * An unknown control frame is preserved as a typed error (never dropped-as-ok).
//   * Encoding accepts IPv4 data and rejects IPv6 outright (IPv4-only, no IPv6).
//   * The API/variant set has NO DTLS and NO UDP variant.
//
// The API P40-I must implement in `exv_vpn_cstp::codec`:
//
//   pub const CSTP_HEADER_LEN: usize = 3;
//   pub const CSTP_MAX_PAYLOAD: usize = 4096;        // bounded MTU
//   pub const CSTP_PACKET_TYPE_DATA: u8 = 0x01;
//   pub const CSTP_PACKET_TYPE_KEEPALIVE: u8 = 0x02;
//
//   #[derive(Debug, Clone, PartialEq, Eq)]
//   pub enum CstpFrame {
//       Data(Vec<u8>),
//       Control { kind: u8, body: Vec<u8> },
//   }
//
//   #[derive(Debug, Clone, PartialEq, Eq)]
//   pub enum CodecError {
//       ShortHeader,
//       BadLength,
//       OversizePayload { declared: usize, limit: usize },
//       UnknownControl(u8),
//       Truncated,          // EOF with a partial frame buffered
//       Ipv6NotSupported,
//   }
//
//   pub struct Codec { /* internal buffered byte stream */ }
//
//   impl Codec {
//       pub fn new() -> Self;
//       pub fn feed(&mut self, chunk: &[u8]);                        // append bytes
//       pub fn decode(&mut self) -> Result<Option<CstpFrame>, CodecError>;
//           // Ok(None) => needs more bytes; Ok(Some(f)) => decoded & consumed f;
//           // Err(e)   => the frame is rejected (buffer is NOT advanced past the header).
//       pub fn finish(self) -> Result<(), CodecError>;               // EOF: partial frame => Err
//       pub fn encode(&self, frame: &CstpFrame) -> Result<Vec<u8>, CodecError>;
//   }

use exv_vpn_cstp::codec::{
    CSTP_HEADER_LEN, CSTP_MAX_PAYLOAD, CSTP_PACKET_TYPE_DATA, Codec, CodecError, CstpFrame,
};

/// Build a raw on-wire CSTP data frame: [type, len_hi, len_lo, ...payload].
fn raw_data_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    assert!(len <= u16::MAX as usize, "test payload too large");
    let mut out = Vec::with_capacity(CSTP_HEADER_LEN + payload.len());
    out.extend_from_slice(&[0x53, 0x54, 0x46, 0x01]); // 'S' 'T' 'F' version
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.push(CSTP_PACKET_TYPE_DATA);
    out.push(0x00);
    out.extend_from_slice(payload);
    out
}

/// Build a raw on-wire CSTP control frame with an arbitrary packet-type byte.
fn raw_frame_with_type(packet_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    assert!(len <= u16::MAX as usize, "test body too large");
    let mut out = Vec::with_capacity(CSTP_HEADER_LEN + body.len());
    out.extend_from_slice(&[0x53, 0x54, 0x46, 0x01]); // 'S' 'T' 'F' version
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.push(packet_type);
    out.push(0x00);
    out.extend_from_slice(body);
    out
}

/// Feed `chunks` into a fresh codec and return the sequence of decoded frames.
fn decode_all(chunks: &[&[u8]]) -> Result<Vec<CstpFrame>, CodecError> {
    let mut codec = Codec::new();
    let mut out = Vec::new();
    for chunk in chunks {
        codec.feed(chunk);
    }
    loop {
        match codec.decode()? {
            Some(frame) => out.push(frame),
            None => break,
        }
    }
    Ok(out)
}

#[test]
fn decodes_one_frame() {
    // A single complete frame in the buffer decodes to exactly one Data frame.
    let payload: Vec<u8> = (0u8..10).collect();
    let wire = raw_data_frame(&payload);
    let frames = decode_all(&[&wire]).expect("one complete frame decodes");
    assert_eq!(frames, vec![CstpFrame::Data(payload)]);
}

#[test]
fn decodes_fragmented_header() {
    // The 3-byte header arrives one byte at a time; no frame is emitted until the
    // header is complete, and decode() reports Ok(None) (needs more) in between.
    let payload: Vec<u8> = (0u8..10).collect();
    let wire = raw_data_frame(&payload);
    let mut codec = Codec::new();
    for i in 0..CSTP_HEADER_LEN {
        codec.feed(&wire[i..i + 1]);
        assert_eq!(codec.decode().unwrap(), None, "header still incomplete");
    }
    // Header complete; payload present. The frame now decodes.
    codec.feed(&wire[CSTP_HEADER_LEN..]);
    assert_eq!(
        codec.decode().unwrap(),
        Some(CstpFrame::Data(payload)),
        "complete fragment delivers the frame"
    );
    assert_eq!(codec.decode().unwrap(), None, "no second frame");
}

#[test]
fn decodes_fragmented_payload() {
    // A full header arrives, then the payload in two pieces; no frame is emitted
    // until the entire payload is buffered.
    let payload: Vec<u8> = (0u8..10).collect();
    let wire = raw_data_frame(&payload);
    let split = CSTP_HEADER_LEN + 4;
    let mut codec = Codec::new();
    codec.feed(&wire[..CSTP_HEADER_LEN]);
    codec.feed(&wire[CSTP_HEADER_LEN..split]);
    assert_eq!(codec.decode().unwrap(), None, "payload still incomplete");
    codec.feed(&wire[split..]);
    assert_eq!(
        codec.decode().unwrap(),
        Some(CstpFrame::Data(payload)),
        "complete payload delivers the frame"
    );
    assert_eq!(codec.decode().unwrap(), None, "no second frame");
}

#[test]
fn decodes_coalesced_frames() {
    // Two complete frames in a single buffer decode as two distinct frames, left to right.
    let a: Vec<u8> = (0u8..4).collect();
    let b: Vec<u8> = (100u8..106).collect();
    let mut wire = raw_data_frame(&a);
    wire.extend_from_slice(&raw_data_frame(&b));
    let frames = decode_all(&[&wire]).expect("coalesced frames decode");
    assert_eq!(frames, vec![CstpFrame::Data(a), CstpFrame::Data(b)]);
}

#[test]
fn rejects_short_header() {
    // A header shorter than CSTP_HEADER_LEN can never be completed once the stream
    // ends (EOF); it must be an error, not a clean finish and not a dropped frame.
    let mut codec = Codec::new();
    codec.feed(&[CSTP_PACKET_TYPE_DATA, 0x00]);
    assert_eq!(codec.decode().unwrap(), None, "2 bytes is not yet a header");
    assert_eq!(
        codec.finish(),
        Err(CodecError::ShortHeader),
        "EOF with an incomplete header is an error"
    );
}

#[test]
fn rejects_bad_length() {
    // A data frame declaring a zero-length payload is malformed (an IP packet can
    // never be empty) and must be rejected by the typed CodecError::BadLength.
    let wire = raw_frame_with_type(CSTP_PACKET_TYPE_DATA, &[]);
    let mut codec = Codec::new();
    codec.feed(&wire);
    assert_eq!(
        codec.decode(),
        Err(CodecError::BadLength),
        "zero-length data frame is bad"
    );
}

#[test]
fn rejects_oversize_payload_before_allocate() {
    // A lying header declares a payload far above the bounded MTU. The codec must
    // reject it immediately, before any allocation of the declared size, and must
    // NOT report "needs more bytes" while it waits to buffer a multi-KiB payload.
    let declared = 0xFFFFusize; // 65535, far above CSTP_MAX_PAYLOAD
    assert!(declared > CSTP_MAX_PAYLOAD, "test precondition on the MTU bound");
    let wire = raw_frame_with_type(CSTP_PACKET_TYPE_DATA, &[]);
    // Overwrite the STF length field ([4..5]) to declare `declared` while only
    // the header is present.
    let mut lying_header = wire[..CSTP_HEADER_LEN].to_vec();
    lying_header[4] = (declared >> 8) as u8;
    lying_header[5] = (declared & 0xff) as u8;

    let mut codec = Codec::new();
    codec.feed(&lying_header); // only 3 bytes available; NO payload supplied
    assert_eq!(
        codec.decode(),
        Err(CodecError::OversizePayload {
            declared,
            limit: CSTP_MAX_PAYLOAD,
        }),
        "oversize declared length is rejected before payload arrives / is allocated"
    );
}

#[test]
fn preserves_unknown_control_as_typed_error() {
    // An unrecognized control packet type must surface as a typed error carrying the
    // kind byte — never silently dropped-as-ok, never mis-decoded as data.
    let unknown_kind = 0x20u8;
    let body = [0xde, 0xad, 0xbe, 0xef];
    let wire = raw_frame_with_type(unknown_kind, &body);
    let mut codec = Codec::new();
    codec.feed(&wire);
    assert_eq!(
        codec.decode(),
        Err(CodecError::UnknownControl(unknown_kind)),
        "unknown control kind is preserved in the typed error"
    );
}

#[test]
fn encodes_ipv4_data() {
    // Encode a valid IPv4 packet (version nibble 0x4) into a CSTP data frame.
    let ipv4_packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00];
    let codec = Codec::new();
    let encoded = codec
        .encode(&CstpFrame::Data(ipv4_packet.clone()))
        .expect("ipv4 data encodes");
    assert_eq!(&encoded[..3], &[0x53, 0x54, 0x46], "STF magic");
    assert_eq!(encoded[3], 0x01, "STF version");
    assert_eq!(encoded[6], CSTP_PACKET_TYPE_DATA, "data packet type in header");
    let len_field = ((encoded[4] as usize) << 8) | encoded[5] as usize;
    assert_eq!(len_field, ipv4_packet.len(), "header length matches payload");
    assert_eq!(&encoded[CSTP_HEADER_LEN..], &ipv4_packet[..], "payload round-trips");
}

#[test]
fn rejects_ipv6_packet() {
    // Encoding an IPv6 packet (version nibble 0x6) is rejected; the MVP is IPv4-only.
    let ipv6_first_byte: Vec<u8> = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00];
    let codec = Codec::new();
    assert_eq!(
        codec.encode(&CstpFrame::Data(ipv6_first_byte)),
        Err(CodecError::Ipv6NotSupported),
        "ipv6 packet is rejected at encode time"
    );
}

#[test]
fn eof_with_partial_frame_is_error() {
    // A complete header declaring a payload, followed by only part of that payload,
    // then EOF, must be an error (Truncated), not a clean/degenerate finish.
    let payload: Vec<u8> = (0u8..10).collect();
    let wire = raw_data_frame(&payload);
    let cut = wire.len() - 3; // drop the last 3 payload bytes
    let mut codec = Codec::new();
    codec.feed(&wire[..cut]);
    assert_eq!(codec.decode().unwrap(), None, "payload incomplete, needs more");
    assert_eq!(
        codec.finish(),
        Err(CodecError::Truncated),
        "EOF with a partial frame is an error"
    );
}

/// Exhaustive match over the frame variant set. This is the compile-time no-DTLS/no-UDP
/// gate: if P40-I ever adds a `Dtl` or `Udp` variant, this match becomes non-exhaustive
/// and the crate fails to compile (the variant set must forbid DTLS/UDP entirely).
#[allow(dead_code)]
fn frame_is_plain_tls_cstp(frame: CstpFrame) -> bool {
    match frame {
        CstpFrame::Data(_) => true,
        CstpFrame::Control { .. } => true,
    }
}

#[test]
fn codec_has_no_dtls_or_udp_variant() {
    // The CSTP codec drives only a TLS/CSTP byte stream. There is no DTLS record header
    // (0x16 handshake / 0x17 appdata content types) and no UDP datagram framing anywhere
    // in the wire format or the variant set.
    let codec = Codec::new();
    let ipv4_packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c];
    let encoded = codec
        .encode(&CstpFrame::Data(ipv4_packet))
        .expect("ipv4 data encodes");
    assert_eq!(encoded[6], CSTP_PACKET_TYPE_DATA, "CSTP data, not DTLS/UDP");
    assert_ne!(
        encoded[0], 0x16,
        "encoded first byte must not be a DTLS handshake record type"
    );
    assert_ne!(
        encoded[0], 0x17,
        "encoded first byte must not be a DTLS application-data record type"
    );
    // The frame variant set is exactly { Data, Control } — no DTLS/UDP member.
    assert!(frame_is_plain_tls_cstp(CstpFrame::Control {
        kind: CSTP_PACKET_TYPE_DATA,
        body: vec![],
    }));
}