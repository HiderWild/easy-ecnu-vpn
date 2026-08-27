// EXV P40-I: bounded CSTP frame codec.
//
// The codec is a stateful streaming decoder: bytes are fed in and complete frames
// come out one at a time. A partial frame never yields a clean finish.
//
// FRAME FORMAT (2026-08-16 对齐真实 Cisco/AnyConnect "STF" 记录头——此前 3 字节头
// 自创格式导致学校网关无法解析数据帧、不回包（held_ring_sent_bytes=0 实测））：
//   [0..2]='S''T''F'  [3]=0x01  [4..5]=payload_len_be16  [6]=packet_type  [7]=0x00
//   payload_len 上限 0xFFFF（be16）。DATA=0x00（AnyConnect 权威；对齐
//   src/vpn_engine/protocol/cstp.cpp kStf* / kPktData，C++ 稳定版 v3.3.7）。
//
// A declared payload length above the STF ceiling is rejected BEFORE any allocation
// of that size. Unknown control packet types surface as a typed error. Encoding
// accepts IPv4 data and rejects IPv6 outright. The variant set has no DTLS and no
// UDP member — the codec drives only a TLS/CSTP byte stream.

/// Length in bytes of the on-wire CSTP "STF" frame header (8 bytes).
pub const CSTP_HEADER_LEN: usize = 8;

/// STF magic bytes and version (AnyConnect-compatible).
pub const STF_MAGIC: [u8; 3] = [0x53, 0x54, 0x46]; // 'S' 'T' 'F'
pub const STF_VERSION: u8 = 0x01;

/// Bounded maximum payload (MTU-bound: the negotiated tunnel MTU governs what a
/// data frame may carry; the STF wire header's be16 is only the transport ceiling).
pub const CSTP_MAX_PAYLOAD: usize = 4096;

/// CSTP wire packet type for a data (IP) frame (AnyConnect: 0x00).
pub const CSTP_PACKET_TYPE_DATA: u8 = 0x00;

/// CSTP wire packet type for a keepalive control frame (AnyConnect: 0x07).
pub const CSTP_PACKET_TYPE_KEEPALIVE: u8 = 0x07;

/// A decoded CSTP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CstpFrame {
    /// An IP data payload.
    Data(Vec<u8>),
    /// A control frame with its packet type and body. Only `CSTP_PACKET_TYPE_KEEPALIVE`
    /// is recognized on decode; any other control kind is rejected as unknown.
    Control { kind: u8, body: Vec<u8> },
}

/// Typed errors produced by the CSTP codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The stream ended with fewer than `CSTP_HEADER_LEN` bytes buffered.
    ShortHeader,
    /// The STF magic/version header is invalid.
    BadMagic,
    /// A data frame declared a zero-length payload, which is malformed.
    BadLength,
    /// The header declared a payload length above the bounded ceiling.
    OversizePayload { declared: usize, limit: usize },
    /// An unrecognized control packet type was encountered.
    UnknownControl(u8),
    /// The stream ended (EOF) with a partial frame buffered.
    Truncated,
    /// An IPv6 packet was offered for encoding; the MVP is IPv4-only.
    Ipv6NotSupported,
}

/// A stateful streaming CSTP decoder with an internal buffered byte stream.
pub struct Codec {
    buf: Vec<u8>,
}

impl Codec {
    /// Create a new, empty codec.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append a chunk of bytes to the internal buffer.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Attempt to decode one complete frame from the buffer.
    ///
    /// Returns `Ok(None)` when more bytes are needed, `Ok(Some(frame))` when a complete
    /// frame was decoded and consumed, or `Err(e)` when the buffered frame is rejected.
    /// On error the buffer is not advanced past the header.
    pub fn decode(&mut self) -> Result<Option<CstpFrame>, CodecError> {
        if self.buf.len() < CSTP_HEADER_LEN {
            return Ok(None);
        }

        // STF header: 'S''T''F' + version 0x01 + len_be16 + type + 0x00.
        if self.buf[0..3] != STF_MAGIC || self.buf[3] != STF_VERSION {
            return Err(CodecError::BadMagic);
        }
        let declared = ((self.buf[4] as usize) << 8) | self.buf[5] as usize;
        let packet_type = self.buf[6];

        // Reject an oversize declared length before buffering or allocating the payload.
        if declared > CSTP_MAX_PAYLOAD {
            return Err(CodecError::OversizePayload {
                declared,
                limit: CSTP_MAX_PAYLOAD,
            });
        }
        let total = CSTP_HEADER_LEN + declared;
        if self.buf.len() < total {
            return Ok(None);
        }

        let payload = self.buf[CSTP_HEADER_LEN..total].to_vec();
        self.buf.drain(..total);

        match packet_type {
            CSTP_PACKET_TYPE_DATA => {
                if payload.is_empty() {
                    return Err(CodecError::BadLength);
                }
                Ok(Some(CstpFrame::Data(payload)))
            }
            CSTP_PACKET_TYPE_KEEPALIVE => Ok(Some(CstpFrame::Control {
                kind: packet_type,
                body: payload,
            })),
            other => Err(CodecError::UnknownControl(other)),
        }
    }

    /// Signal EOF: fewer than `CSTP_HEADER_LEN` bytes buffered is `ShortHeader`;
    /// a complete header with a partial payload is `Truncated`; a clean buffer is Ok.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.buf.is_empty() {
            Ok(())
        } else if self.buf.len() < CSTP_HEADER_LEN {
            Err(CodecError::ShortHeader)
        } else {
            Err(CodecError::Truncated)
        }
    }

    /// Encode a frame into the on-wire STF byte form.
    pub fn encode(&self, frame: &CstpFrame) -> Result<Vec<u8>, CodecError> {
        match frame {
            CstpFrame::Data(payload) => {
                // IPv4-only MVP: reject IPv6 packets at encode time.
                if payload.first().is_some_and(|b| (b >> 4) == 6) {
                    return Err(CodecError::Ipv6NotSupported);
                }
                Self::encode_raw(CSTP_PACKET_TYPE_DATA, payload)
            }
            CstpFrame::Control { kind, body } => Self::encode_raw(*kind, body),
        }
    }

    /// Encode a raw packet type + payload into the STF byte form.
    pub fn encode_raw(packet_type: u8, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
        if payload.len() > CSTP_MAX_PAYLOAD {
            return Err(CodecError::OversizePayload {
                declared: payload.len(),
                limit: CSTP_MAX_PAYLOAD,
            });
        }
        let mut out = Vec::with_capacity(CSTP_HEADER_LEN + payload.len());
        out.extend_from_slice(&STF_MAGIC);
        out.push(STF_VERSION);
        out.push((payload.len() >> 8) as u8);
        out.push((payload.len() & 0xFF) as u8);
        out.push(packet_type);
        out.push(0x00);
        out.extend_from_slice(payload);
        Ok(out)
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
