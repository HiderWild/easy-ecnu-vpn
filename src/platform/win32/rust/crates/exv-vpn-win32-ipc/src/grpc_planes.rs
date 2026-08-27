// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W12-I: the plane-isolation model for the Win32 native runtime. Each plane (control/data) rides
// its own physical connection (WSP1 §3) and is budgeted independently (WSP1 §7): an oversize
// pre-auth frame is refused WITHOUT being dispatched, an unauthorized plane never dispatches, and
// a packet-plane flood must never block the control plane's Stop path. The model is pure
// in-memory state; no real Named Pipe is needed.

use crate::connection_binding::{ConnectionBinding, Plane};
use crate::limits::PlaneLimits;

/// Per-plane isolation over the two physical connections of a Win32 runtime.
///
/// Control and packet budgets are tracked separately so backpressure on one plane can never
/// block the other (a packet flood stays over budget on `Packet` while `Control` keeps
/// admitting its own frames).
pub struct PlaneIsolation {
    /// The physical connection bound to the control plane, if any.
    control: Option<ConnectionBinding>,
    /// The physical connection bound to the packet plane, if any.
    packet: Option<ConnectionBinding>,
    /// Number of frames admitted on the control plane.
    control_frames: usize,
    /// Number of frames admitted on the packet plane.
    packet_frames: usize,
    /// Cumulative bytes admitted on the control plane.
    control_buffer: usize,
    /// Cumulative bytes admitted on the packet plane.
    packet_buffer: usize,
    /// The pre-auth buffer ceiling used by `is_over_budget` (WSP1 §7, frozen at 64 KiB).
    preauth_max_buffer_bytes: usize,
}

impl PlaneIsolation {
    /// Starts an isolation model with no connections bound and no dispatched frames.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            control: None,
            packet: None,
            control_frames: 0,
            packet_frames: 0,
            control_buffer: 0,
            packet_buffer: 0,
            preauth_max_buffer_bytes: PlaneLimits::mvp().preauth_max_buffer_bytes,
        }
    }

    /// Binds `binding` to its plane. A plane may hold at most one physical connection (WSP1 §3);
    /// registering a second one for the same plane is refused.
    ///
    /// # Errors
    /// Returns `Err("plane already bound")` when the plane already holds a connection.
    pub fn register_connection(&mut self, binding: ConnectionBinding) -> Result<(), &'static str> {
        let slot = match binding.plane() {
            Plane::Control => &mut self.control,
            Plane::Packet => &mut self.packet,
        };
        if slot.is_some() {
            return Err("plane already bound");
        }
        *slot = Some(binding);
        Ok(())
    }

    /// Returns the physical connection bound to `plane`, if one is registered.
    #[must_use]
    pub const fn connection_for(&self, plane: Plane) -> Option<&ConnectionBinding> {
        match plane {
            Plane::Control => self.control.as_ref(),
            Plane::Packet => self.packet.as_ref(),
        }
    }

    /// Admits one frame of `frame_len` bytes on `plane` against the pre-auth `limits`.
    ///
    /// A frame over `limits.preauth_max_message_bytes` is refused WITHOUT being dispatched: the
    /// frame/buffer budget is left untouched and no large buffer is pre-allocated from its
    /// declared length (WSP1 §7). Otherwise the frame is counted and its length added to the
    /// plane's buffer.
    ///
    /// # Errors
    /// Returns `Err("frame over max message")` when `frame_len` exceeds the pre-auth message
    /// ceiling; the rejected frame is never counted toward the budget.
    pub fn admit_frame(
        &mut self,
        plane: Plane,
        frame_len: usize,
        limits: &PlaneLimits,
    ) -> Result<(), &'static str> {
        if frame_len > limits.preauth_max_message_bytes {
            return Err("frame over max message");
        }
        match plane {
            Plane::Control => {
                self.control_frames += 1;
                self.control_buffer += frame_len;
            }
            Plane::Packet => {
                self.packet_frames += 1;
                self.packet_buffer += frame_len;
            }
        }
        Ok(())
    }

    /// Returns whether `plane` has exceeded its pre-auth buffer budget.
    ///
    /// A plane is over budget only once its cumulative admitted bytes strictly exceed
    /// `preauth_max_buffer_bytes`: a single max-size frame still "fits exactly" at the budget,
    /// while a second one pushes the plane over.
    #[must_use]
    pub const fn is_over_budget(&self, plane: Plane) -> bool {
        match plane {
            Plane::Control => self.control_buffer > self.preauth_max_buffer_bytes,
            Plane::Packet => self.packet_buffer > self.preauth_max_buffer_bytes,
        }
    }

    /// Returns the number of frames admitted on the control plane.
    #[must_use]
    pub const fn control_frames(&self) -> usize {
        self.control_frames
    }

    /// Returns the number of frames admitted on the packet plane.
    #[must_use]
    pub const fn packet_frames(&self) -> usize {
        self.packet_frames
    }
}

impl Default for PlaneIsolation {
    fn default() -> Self {
        Self::new()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
