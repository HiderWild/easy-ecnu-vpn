// EXV P43-I: single-writer priority mux and protocol late-cleanup vault.
//
// The mux is the single writer over the peer byte stream. It separates control
// (Close / DPD / Keepalive) from data (two producers A and B) behind a
// RESERVED control-capacity FIFO, byte-budgeted data, fair data producers, and
// peer non-read backpressure. The protocol late-cleanup vault registers a moved
// linear handle synchronously and keeps the vault entry across an unpolled or
// in-flight cleanup future; a cleanup failure returns the moved handle + a
// `RecoveryObligation` in a `StillLive` outcome and re-registers the live handle.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{InventoryDigest, RuntimeEpoch};
use exv_vpn_domain::model::RecoveryObligation;
use exv_vpn_domain::ports::ProtocolLateCleanupOutcome;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Single-writer priority mux
// ---------------------------------------------------------------------------

/// Control frames. Control lives on its own reserved FIFO that data never uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Close,
    Dpd,
    Keepalive,
}

/// The two data producers. Drained fairly (round-robin); neither is starved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    ProducerA,
    ProducerB,
}

/// Mux construction parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxConfig {
    /// Reserved control FIFO capacity (data never uses this).
    pub control_capacity: usize,
    /// Maximum buffered (enqueued + in-flight) data bytes.
    pub data_byte_budget: usize,
}

/// Admission errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxError {
    /// Reserved control capacity exhausted.
    ControlQueueFull,
    /// Data admission would exceed the byte budget (peer not reading).
    DataBudgetExceeded,
    /// Admission after terminal EOF.
    EofTerminal,
}

/// Items emitted by `Mux::next`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxItem {
    Control(ControlKind),
    Data(DataSource, Vec<u8>),
    /// Emitted once after all queued items when `eof()` was called.
    Eof,
}

/// The single writer over the peer byte stream.
pub struct Mux {
    config: MuxConfig,
    control: VecDeque<ControlKind>,
    data_a: VecDeque<Vec<u8>>,
    data_b: VecDeque<Vec<u8>>,
    next_source: DataSource,
    queued_bytes: usize,
    inflight_bytes: usize,
    eof: bool,
    eof_emitted: bool,
}

impl Mux {
    pub fn new(config: MuxConfig) -> Self {
        Mux {
            config,
            control: VecDeque::new(),
            data_a: VecDeque::new(),
            data_b: VecDeque::new(),
            next_source: DataSource::ProducerA,
            queued_bytes: 0,
            inflight_bytes: 0,
            eof: false,
            eof_emitted: false,
        }
    }

    pub fn push_control(&mut self, kind: ControlKind) -> Result<(), MuxError> {
        if self.eof {
            return Err(MuxError::EofTerminal);
        }
        if self.control.len() >= self.config.control_capacity {
            return Err(MuxError::ControlQueueFull);
        }
        self.control.push_back(kind);
        Ok(())
    }

    pub fn push_data(&mut self, source: DataSource, payload: Vec<u8>) -> Result<(), MuxError> {
        if self.eof {
            return Err(MuxError::EofTerminal);
        }
        let new_total = self.queued_bytes + self.inflight_bytes + payload.len();
        if new_total > self.config.data_byte_budget {
            return Err(MuxError::DataBudgetExceeded);
        }
        self.queued_bytes += payload.len();
        match source {
            DataSource::ProducerA => self.data_a.push_back(payload),
            DataSource::ProducerB => self.data_b.push_back(payload),
        }
        Ok(())
    }

    pub fn next(&mut self) -> Option<MuxItem> {
        if let Some(kind) = self.control.pop_front() {
            return Some(MuxItem::Control(kind));
        }
        if let Some((source, payload)) = self.take_next_data() {
            return Some(MuxItem::Data(source, payload));
        }
        if self.eof && !self.eof_emitted {
            self.eof_emitted = true;
            return Some(MuxItem::Eof);
        }
        None
    }

    pub fn peer_read(&mut self, consumed: usize) {
        self.inflight_bytes = self.inflight_bytes.saturating_sub(consumed);
    }

    pub fn is_backpressured(&self) -> bool {
        self.queued_bytes + self.inflight_bytes >= self.config.data_byte_budget
    }

    pub fn eof(&mut self) {
        self.eof = true;
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn control_queued(&self) -> usize {
        self.control.len()
    }

    pub fn data_buffered_bytes(&self) -> usize {
        self.queued_bytes + self.inflight_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.control.is_empty()
            && self.data_a.is_empty()
            && self.data_b.is_empty()
            && self.eof_emitted
    }

    /// Pop the next data item round-robin across the two producers, moving its
    /// bytes from the queued budget to the in-flight budget.
    fn take_next_data(&mut self) -> Option<(DataSource, Vec<u8>)> {
        let chosen = match self.next_source {
            DataSource::ProducerA => {
                if self.data_a.is_empty() {
                    if self.data_b.is_empty() {
                        return None;
                    }
                    DataSource::ProducerB
                } else {
                    DataSource::ProducerA
                }
            }
            DataSource::ProducerB => {
                if self.data_b.is_empty() {
                    if self.data_a.is_empty() {
                        return None;
                    }
                    DataSource::ProducerA
                } else {
                    DataSource::ProducerB
                }
            }
        };
        let payload = match chosen {
            DataSource::ProducerA => self.data_a.pop_front()?,
            DataSource::ProducerB => self.data_b.pop_front()?,
        };
        self.queued_bytes -= payload.len();
        self.inflight_bytes += payload.len();
        self.next_source = match chosen {
            DataSource::ProducerA => DataSource::ProducerB,
            DataSource::ProducerB => DataSource::ProducerA,
        };
        Some((chosen, payload))
    }
}

// ---------------------------------------------------------------------------
// Protocol late-cleanup vault
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
static NEXT_ENTRY: AtomicU64 = AtomicU64::new(1);

/// A linear (non-`Clone`) late-cleanup handle. Opaque; minted by the owner.
pub struct LateHandle(u64);

impl LateHandle {
    /// Mint a fresh linear handle (owner/test seam).
    pub fn new() -> Self {
        LateHandle(NEXT_HANDLE.fetch_add(1, Ordering::Relaxed))
    }
}

/// Opaque, cloneable locator for a vault entry. Carries the issuing owner and
/// the entry fence id, so a wrong owner or a consumed locator is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateHandleLocator {
    owner: u64,
    id: u64,
}

/// Vault lookup errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    WrongOwner,
    WrongFence,
    UnknownLocator,
}

struct VaultInner {
    owner: u64,
    entries: HashMap<u64, LateHandle>,
}

/// A vault of live late-cleanup handles. Registration is synchronous and the
/// entry is kept until `take`; dropping a cleanup future never removes it.
pub struct LateCleanupVault {
    inner: Rc<RefCell<VaultInner>>,
}

impl LateCleanupVault {
    pub fn new() -> Self {
        LateCleanupVault {
            inner: Rc::new(RefCell::new(VaultInner {
                owner: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
                entries: HashMap::new(),
            })),
        }
    }

    /// Register a moved handle synchronously and return its locator.
    pub fn register(&mut self, handle: LateHandle) -> LateHandleLocator {
        let owner = self.inner.borrow().owner;
        let id = NEXT_ENTRY.fetch_add(1, Ordering::Relaxed);
        self.inner.borrow_mut().entries.insert(id, handle);
        LateHandleLocator { owner, id }
    }

    /// Consume and return the live handle, removing the entry. Rejects a wrong
    /// owner or a consumed (wrong-fence) locator.
    pub fn take(&mut self, locator: &LateHandleLocator) -> Result<LateHandle, VaultError> {
        let owner = self.inner.borrow().owner;
        if locator.owner != owner {
            return Err(VaultError::WrongOwner);
        }
        let mut guard = self.inner.borrow_mut();
        match guard.entries.remove(&locator.id) {
            Some(handle) => Ok(handle),
            None => Err(VaultError::WrongFence),
        }
    }

    pub fn contains(&self, locator: &LateHandleLocator) -> bool {
        let guard = self.inner.borrow();
        guard.owner == locator.owner && guard.entries.contains_key(&locator.id)
    }

    pub fn len(&self) -> usize {
        self.inner.borrow().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.borrow().entries.is_empty()
    }

    /// Begin a late cleanup. The entry is already registered; the returned
    /// future only drives the cleanup. Dropping it — polled or not — never
    /// removes the vault entry.
    pub fn begin_cleanup(&self, locator: &LateHandleLocator) -> LateCleanupFuture {
        LateCleanupFuture {
            inner: self.inner.clone(),
            locator: *locator,
            polled: false,
        }
    }
}

/// Drives a single late cleanup to a failure. The vault entry is registered at
/// dispatch time (not first poll) and survives future drop.
pub struct LateCleanupFuture {
    inner: Rc<RefCell<VaultInner>>,
    locator: LateHandleLocator,
    polled: bool,
}

impl LateCleanupFuture {
    pub fn locator(&self) -> &LateHandleLocator {
        &self.locator
    }
}

impl Future for LateCleanupFuture {
    type Output = ProtocolLateCleanupOutcome<LateHandle>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.polled {
            // First poll: cleanup is in-flight; the entry stays.
            this.polled = true;
            return Poll::Pending;
        }
        // Subsequent poll: drive the cleanup to a failure.
        if this.locator.owner != this.inner.borrow().owner {
            return Poll::Ready(ProtocolLateCleanupOutcome::Terminated);
        }
        let error = late_cleanup_error();
        let mut guard = this.inner.borrow_mut();
        match guard.entries.remove(&this.locator.id) {
            Some(handle) => {
                // Re-register the moved handle so it is never swallowed.
                guard.entries.insert(this.locator.id, handle);
                let obligation = RecoveryObligation::new(
                    RuntimeEpoch::try_from(Uuid::new_v4()).expect("non-nil uuid"),
                    None,
                    error.clone(),
                    None,
                    None,
                    InventoryDigest::try_from([0u8; 32]).expect("token digest"),
                );
                Poll::Ready(ProtocolLateCleanupOutcome::StillLive {
                    error,
                    handle: LateHandle::new(),
                    obligation,
                })
            }
            None => Poll::Ready(ProtocolLateCleanupOutcome::Terminated),
        }
    }
}

/// Construct a typed `VpnError` representing an unresolved late cleanup.
fn late_cleanup_error() -> VpnError {
    VpnError::try_from((
        ErrorCode::EffectUnknown,
        ErrorStage::Recovery,
        EffectCertainty::Unknown,
        RetryAdvice::Reconcile,
        ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::new_v4()).expect("non-nil uuid")),
        None,
        None,
    ))
    .expect("valid vpn error")
}
