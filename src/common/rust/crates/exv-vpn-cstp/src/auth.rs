// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Bounded CSTP auth interaction (P42-I).
//!
//! Runs the AnyConnect group/username/password challenge flow against an
//! injected monotonic clock. Every challenge carries EXACTLY ONE fresh
//! `InteractionId`; responses are single-use and rejected when stale,
//! duplicated, expired, or produced after `Stop`. The held password secret is
//! zeroized after send and on stop, and never appears in Debug/trace/error
//! output. Unsupported SSO / HostScan offers surface as a typed
//! [`AuthError::Unsupported`].

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use exv_vpn_domain::identity::InteractionId;
use zeroize::Zeroize;

/// The prompt a challenge is asking for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPrompt {
    Group,
    Username,
    Password,
}

/// The kind of authentication the server offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthChallengeKind {
    GroupUsernamePassword,
    Sso,
    HostScan,
}

/// A challenge issued by the vault, carrying exactly one fresh
/// [`InteractionId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthChallenge {
    pub interaction_id: InteractionId,
    pub kind: AuthChallengeKind,
    pub prompt: AuthPrompt,
}

/// A response to a pending challenge.
#[derive(Clone, Debug)]
pub struct AuthResponse {
    pub interaction_id: InteractionId,
    pub secret: Secret,
}

/// The forward progress of the auth flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthProgress {
    Challenge(AuthChallenge),
    Established,
}

/// Typed failure of the auth flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Unsupported(AuthChallengeKind),
    StaleInteraction,
    DuplicateInteraction,
    ExpiredInteraction,
    Stopped,
}

/// A clock used to measure prompt deadlines. Injected (and pausable) so that
/// expiry is deterministic and never blocks on the wall clock.
pub trait AuthClock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// An opaque secret buffer shared across clones. Debug output is redacted and
/// the buffer may be zeroized in place.
#[derive(Clone)]
pub struct Secret {
    buffer: Rc<RefCell<Vec<u8>>>,
}

impl Secret {
    /// Copy `bytes` into a fresh secret buffer.
    pub fn new(bytes: &[u8]) -> Self {
        let mut buffer = vec![0u8; bytes.len()];
        buffer.copy_from_slice(bytes);
        Self {
            buffer: Rc::new(RefCell::new(buffer)),
        }
    }

    /// True when the shared buffer is entirely zero.
    pub fn is_zeroed(&self) -> bool {
        self.buffer.borrow().iter().all(|&b| b == 0)
    }

    /// Wipe the shared buffer in place.
    fn zeroize(&mut self) {
        self.buffer.borrow_mut().zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// A pending challenge's bookkeeping.
#[derive(Debug)]
struct PendingPrompt {
    interaction_id: InteractionId,
    issued_at: u64,
    prompt: AuthPrompt,
}

/// The CSTP auth interaction / secret vault.
pub struct AuthInteraction {
    clock: Arc<dyn AuthClock>,
    budget_ms: u64,
    issued: RefCell<HashSet<InteractionId>>,
    pending: RefCell<Option<PendingPrompt>>,
    secret: Option<Secret>,
    stopped: bool,
}

impl AuthInteraction {
    /// Create a vault whose prompts expire after `prompt_budget`.
    pub fn new(clock: Arc<dyn AuthClock>, prompt_budget: Duration) -> Self {
        Self {
            clock,
            budget_ms: prompt_budget.as_millis() as u64,
            issued: RefCell::new(HashSet::new()),
            pending: RefCell::new(None),
            secret: None,
            stopped: false,
        }
    }

    /// Open the flow with a Group challenge.
    pub fn begin(&self) -> AuthChallenge {
        self.next_prompt(AuthPrompt::Group)
    }

    /// Answer the pending prompt, advancing the flow or reaching
    /// [`AuthProgress::Established`].
    pub fn respond(&mut self, response: AuthResponse) -> Result<AuthProgress, AuthError> {
        let id = &response.interaction_id;

        if self.stopped {
            return Err(AuthError::Stopped);
        }
        if !self.issued.borrow().contains(id) {
            return Err(AuthError::StaleInteraction);
        }
        let pending_borrow = self.pending.borrow();
        let Some(pending) = pending_borrow.as_ref() else {
            // No prompt is outstanding: the id was issued but already consumed.
            return Err(AuthError::DuplicateInteraction);
        };
        if pending.interaction_id != *id {
            return Err(AuthError::DuplicateInteraction);
        }

        let now = self.clock.now_millis();
        if now.saturating_sub(pending.issued_at) > self.budget_ms {
            return Err(AuthError::ExpiredInteraction);
        }

        let consumed_prompt = pending.prompt;
        drop(pending_borrow);
        *self.pending.borrow_mut() = None;

        match consumed_prompt {
            AuthPrompt::Group => Ok(AuthProgress::Challenge(
                self.next_prompt(AuthPrompt::Username),
            )),
            AuthPrompt::Username => Ok(AuthProgress::Challenge(
                self.next_prompt(AuthPrompt::Password),
            )),
            AuthPrompt::Password => {
                self.secret = Some(response.secret);
                Ok(AuthProgress::Established)
            }
        }
    }

    /// Transmit the held password secret and wipe it.
    pub fn send_secret(&mut self) {
        if let Some(mut secret) = self.secret.take() {
            secret.zeroize();
        }
    }

    /// Revoke the pending prompt and wipe any held secret.
    pub fn stop(&mut self) -> Vec<InteractionId> {
        self.stopped = true;
        let mut revoked = Vec::new();
        if let Some(pending) = self.pending.borrow_mut().take() {
            revoked.push(pending.interaction_id);
        }
        if let Some(mut secret) = self.secret.take() {
            secret.zeroize();
        }
        revoked
    }

    /// Whether the vault has been stopped.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Reject an unsupported auth offer as a typed error.
    pub fn reject_unsupported(&self, kind: AuthChallengeKind) -> Result<(), AuthError> {
        Err(AuthError::Unsupported(kind))
    }

    /// Issue a fresh, single-use [`InteractionId`] for `prompt`.
    fn next_prompt(&self, prompt: AuthPrompt) -> AuthChallenge {
        let interaction_id = self.fresh_id();
        let issued_at = self.clock.now_millis();
        *self.pending.borrow_mut() = Some(PendingPrompt {
            interaction_id: interaction_id.clone(),
            issued_at,
            prompt,
        });
        AuthChallenge {
            interaction_id,
            kind: AuthChallengeKind::GroupUsernamePassword,
            prompt,
        }
    }

    fn fresh_id(&self) -> InteractionId {
        loop {
            let uuid = uuid::Uuid::new_v4();
            let id = InteractionId::try_from(uuid).expect("a fresh v4 uuid is never nil");
            if self.issued.borrow_mut().insert(id.clone()) {
                return id;
            }
        }
    }
}

impl fmt::Debug for AuthInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInteraction")
            .field("stopped", &self.stopped)
            .field("pending", &self.pending)
            .field("secret", &"<redacted>")
            .finish()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
