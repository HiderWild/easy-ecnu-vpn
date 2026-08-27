// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W12-I: the plane-to-connection binding. Control and data ride two independent physical
// connections (WSP1 §3: control 与 data 使用两条独立物理连接), each its own
// CreateNamedPipeW + ConnectNamedPipe + 独立读/写 in the real runtime.

/// The logical traffic plane of a named-pipe connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    /// The control plane: signaling and RPC (its Stop path must stay live under packet backpressure).
    Control,
    /// The data plane: packet traffic.
    Packet,
}

/// A physical named-pipe connection bound to exactly one plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBinding {
    /// The plane this physical connection serves.
    plane: Plane,
    /// The Win32 named-pipe name this connection is bound to.
    pipe_name: String,
}

impl ConnectionBinding {
    /// Binds `pipe_name` to `plane` as one physical connection.
    #[must_use]
    pub const fn new(plane: Plane, pipe_name: String) -> Self {
        Self { plane, pipe_name }
    }

    /// Returns the plane this connection serves.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        self.plane
    }

    /// Returns the Win32 pipe name this connection is bound to.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
