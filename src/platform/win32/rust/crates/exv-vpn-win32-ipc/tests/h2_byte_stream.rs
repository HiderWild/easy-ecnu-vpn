// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W10-T terra: h2 byte-stream over a Windows byte-mode Named Pipe. These tests pin the
// NamedPipeByteStream API that W10-I implements in exv_vpn_win32_ipc::named_pipe_io.
// The frozen WSP1 facts (native-pipe-facts.md) are the contract: byte mode carries the
// h2 preface across partial I/O; message mode is a wrong mutant; control/data are two
// separate physical pipes.
//
// The tests run REAL local Named Pipe I/O (server + client); the client side runs on a
// std::thread. Deterministic payloads only.

use std::thread;
use std::time::Duration;

use exv_vpn_win32_ipc::named_pipe_io::{NamedPipeByteStream, PipeIoError};

/// The 24-byte HTTP/2 connection preface (RFC 9113 §3.5).
fn h2_preface() -> &'static [u8] {
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
}

/// A unique per-test pipe name so parallel tests never collide.
fn pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-w10-{tag}-{}", std::process::id())
}

/// Kills 'message-mode framing breaks the preface' and 'read does not reassemble partial data'.
#[test]
fn byte_stream_carries_h2_preface_across_partial_io() {
    let name = pipe_name("preface");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let client = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        let preface = h2_preface();
        c.write_all(&preface[0..8]).expect("write chunk 1");
        c.write_all(&preface[8..16]).expect("write chunk 2");
        c.write_all(&preface[16..]).expect("write chunk 3");
    });

    server.connect().expect("server connect");
    let mut got = Vec::with_capacity(24);
    let mut buf = [0u8; 5];
    while got.len() < 24 {
        let n = server.read(&mut buf).expect("read chunk");
        assert!(n > 0, "server read must make progress");
        got.extend_from_slice(&buf[..n]);
    }
    client.join().expect("client thread joins");
    assert_eq!(got, h2_preface(), "h2 preface must reassemble byte-exact across partial I/O");
}

/// Kills 'pipe created in message mode'.
#[test]
fn byte_stream_reject_message_mode_is_byte_mode() {
    let name = pipe_name("bytemode");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    assert!(server.is_byte_mode(), "server pipe must be created in byte mode, never message mode");
}

/// Kills 'read returns an error on partial data'.
#[test]
fn partial_read_returns_available_bytes_not_error() {
    let name = pipe_name("partial");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let client = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        c.write_all(b"hi").expect("write short");
    });

    server.connect().expect("server connect");
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).expect("read must not error on partial data");
    assert_eq!(&buf[..n], b"hi", "short write must be read as available bytes, not an error");
    client.join().expect("client thread joins");
}

/// Kills 'write_all drops bytes / read misreads'.
#[test]
fn write_all_then_read_roundtrip() {
    let name = pipe_name("roundtrip");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let payload: Vec<u8> = (0u8..255).collect();
    let payload_len = payload.len();
    let client_payload = payload.clone();
    let client = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        c.write_all(&client_payload).expect("write payload");
    });

    server.connect().expect("server connect");
    let mut got = Vec::with_capacity(payload_len);
    let mut buf = [0u8; 32];
    while got.len() < payload_len {
        let n = server.read(&mut buf).expect("read");
        assert!(n > 0, "read must make progress toward the full payload");
        got.extend_from_slice(&buf[..n]);
    }
    client.join().expect("client thread joins");
    assert_eq!(got, payload, "payload must round-trip byte-exact");
}

/// Kills 'EOF reported as Io error, not PeerClosed'.
#[test]
fn peer_eof_reports_peer_closed() {
    let name = pipe_name("eof");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let client = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        c.write_all(b"done").expect("write");
        drop(c);
    });

    server.connect().expect("server connect");
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).expect("read data before EOF");
    assert_eq!(&buf[..n], b"done");
    let eof = server.read(&mut buf);
    assert!(
        matches!(eof, Err(PipeIoError::PeerClosed)),
        "a closed peer must be reported as PeerClosed, got {eof:?}"
    );
    client.join().expect("client thread joins");
}

/// Kills 'close detaches/forgets pending I/O'.
#[test]
fn close_server_handle_does_not_detach_pending_io() {
    let name = pipe_name("close");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let client = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        thread::sleep(Duration::from_millis(50));
        drop(c);
    });

    server.connect().expect("server connect");
    drop(server);
    client.join().expect("client thread joins");
}

/// Kills 'control and data share one pipe/connection' (WSP1 §3).
#[test]
fn two_pipes_are_independent_physical_connections() {
    let name_a = pipe_name("plane-a");
    let name_b = pipe_name("plane-b");
    let server_a = NamedPipeByteStream::create_server(&name_a, 1).expect("create pipe A");
    let server_b = NamedPipeByteStream::create_server(&name_b, 1).expect("create pipe B");

    let client_a = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name_a).expect("client A");
        c.write_all(b"ping-a").expect("write A");
    });
    let client_b = thread::spawn(move || {
        let mut c = NamedPipeByteStream::connect_client(&name_b).expect("client B");
        c.write_all(b"ping-b").expect("write B");
    });

    server_a.connect().expect("server A connect");
    server_b.connect().expect("server B connect");

    let mut buf_a = [0u8; 32];
    let mut buf_b = [0u8; 32];
    let n_a = server_a.read(&mut buf_a).expect("read A");
    let n_b = server_b.read(&mut buf_b).expect("read B");

    client_a.join().expect("client A joins");
    client_b.join().expect("client B joins");

    assert_eq!(&buf_a[..n_a], b"ping-a", "pipe A must carry only its own payload");
    assert_eq!(&buf_b[..n_b], b"ping-b", "pipe B must carry only its own payload");
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。