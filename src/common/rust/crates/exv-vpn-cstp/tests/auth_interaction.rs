// EXV P42-T: bounded CSTP auth-interaction integration tests for exv-vpn-cstp.
//
// These tests define the exact public API that P42-I must implement in
// `exv_vpn_cstp::auth`. They are expected to be RED (compile error) until P42-I
// implements that auth interaction. The interaction runs the AnyConnect
// group/username/password challenge flow, emits EXACTLY ONE fresh InteractionId
// per challenge, rejects stale/duplicate/expired responses, revokes the prompt on
// Stop, zeroizes the password secret after send and on stop, keeps the secret
// absent from Debug/trace/error output, and treats unsupported SSO/HostScan
// offers as a typed error.
//
// Contract (RNRM-005/008/011, TG-04/TG-SEC):
//   * Group/username/password flow: `begin()` opens with a Group challenge; each
//     `respond()` advances to the next prompt and the final password response
//     yields `AuthProgress::Established`.
//   * One InteractionId per challenge: every challenge carries exactly one
//     `InteractionId` (an `exv_vpn_domain::identity::InteractionId`), fresh and
//     distinct from every earlier challenge; an id is never reused.
//   * Stale rejection: an InteractionId this vault never issued is rejected.
//   * Duplicate rejection: re-answering an already-consumed InteractionId is
//     rejected — ids are single-use.
//   * Expiry rejection: a response arriving after the prompt deadline (measured
//     on an injected/paused clock) is rejected.
//   * Stop revokes the prompt: `stop()` revokes the pending prompt's id and the
//     vault refuses any further response.
//   * Secret lifetime: the vault holds ONLY the password secret in a pending
//     slot; it is wiped (zeroized) after `send_secret()` and on `stop()`.
//   * No secret in output: the password never appears in Debug/trace/error
//     output.
//   * Unsupported auth: SSO / HostScan offers surface as a typed
//     `AuthError::Unsupported(kind)`.
//
// The API P42-I must implement in `exv_vpn_cstp::auth`:
//
//   pub enum AuthPrompt { Group, Username, Password }
//   pub enum AuthChallengeKind { GroupUsernamePassword, Sso, HostScan }
//   pub struct AuthChallenge {
//       pub interaction_id: exv_vpn_domain::identity::InteractionId,
//       pub kind: AuthChallengeKind,
//       pub prompt: AuthPrompt,
//   }
//   pub struct AuthResponse { pub interaction_id: InteractionId, pub secret: Secret }
//   pub enum AuthProgress { Challenge(AuthChallenge), Established }
//   pub enum AuthError {
//       Unsupported(AuthChallengeKind),
//       StaleInteraction,
//       DuplicateInteraction,
//       ExpiredInteraction,
//       Stopped,
//   }
//   pub trait AuthClock: Send + Sync { fn now_millis(&self) -> u64; }
//   pub struct Secret { /* opaque */ }
//   impl Secret {
//       pub fn new(bytes: &[u8]) -> Self;          // copy bytes into the buffer
//       pub fn is_zeroed(&self) -> bool;           // true when the buffer is all zeros
//   }
//   // Secret is Clone (shared handle so tests can observe wiping) and its Debug
//   // output is redacted (never prints the bytes).
//   pub struct AuthInteraction { /* opaque */ }
//   impl AuthInteraction {
//       pub fn new(clock: Arc<dyn AuthClock>, prompt_budget: Duration) -> Self;
//       pub fn begin(&mut self) -> AuthChallenge;              // Group challenge
//       pub fn respond(&mut self, response: AuthResponse)
//           -> Result<AuthProgress, AuthError>;
//       pub fn send_secret(&mut self);                         // transmit + zeroize
//       pub fn stop(&mut self) -> Vec<InteractionId>;          // revoke prompt + zeroize
//       pub fn is_stopped(&self) -> bool;
//       pub fn reject_unsupported(&self, kind: AuthChallengeKind) -> Result<(), AuthError>;
//   }
//
// Mutants this suite must kill:
//   M1 reusable InteractionId (an id is not single-use / two challenges share an id)
//       -> challenge_emits_one_interaction_id, duplicate_response_is_rejected,
//          stale_interaction_is_rejected
//   M2 password clone retained (the secret is not wiped after send / on stop)
//       -> secret_zeroized_after_send, secret_zeroized_on_stop
//   M3 Stop does not revoke the prompt
//       -> stop_revokes_prompt

use exv_vpn_cstp::auth::{
    AuthChallengeKind, AuthClock, AuthError, AuthInteraction, AuthProgress, AuthPrompt,
    AuthResponse, Secret,
};
use exv_vpn_domain::identity::InteractionId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// An injected, paused monotonic clock (millis), NOT the wall clock, so the
// expiry test is deterministic and never sleeps.
// ---------------------------------------------------------------------------

struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    fn at(t: u64) -> Self {
        Self {
            now: AtomicU64::new(t),
        }
    }

    fn advance(&self, by: u64) {
        self.now.fetch_add(by, Ordering::SeqCst);
    }
}

impl AuthClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Test helper: drive the flow from begin() up to (but not including) the
// password response, returning the password challenge's InteractionId.
// ---------------------------------------------------------------------------

fn run_to_password(vault: &mut AuthInteraction) -> InteractionId {
    let group = vault.begin();
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"vpn-group"),
        })
        .expect("group credential advances the flow");
    let AuthProgress::Challenge(username) = username else {
        panic!("group step must return the username challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"alice"),
        })
        .expect("username credential advances the flow");
    let AuthProgress::Challenge(password) = password else {
        panic!("username step must return the password challenge");
    };
    password.interaction_id
}

// ---------------------------------------------------------------------------
// The 10 fixed tests
// ---------------------------------------------------------------------------

#[test]
fn group_username_password_flow() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let group = vault.begin();
    assert_eq!(
        group.kind,
        AuthChallengeKind::GroupUsernamePassword,
        "the MVP flow is group/username/password"
    );
    assert_eq!(group.prompt, AuthPrompt::Group, "begin() opens with a Group challenge");

    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"vpn-group"),
        })
        .expect("group advances to username");
    let AuthProgress::Challenge(username) = username else {
        panic!("group step must return the username challenge");
    };
    assert_eq!(username.prompt, AuthPrompt::Username);

    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"alice"),
        })
        .expect("username advances to password");
    let AuthProgress::Challenge(password) = password else {
        panic!("username step must return the password challenge");
    };
    assert_eq!(password.prompt, AuthPrompt::Password);

    let done = vault
        .respond(AuthResponse {
            interaction_id: password.interaction_id.clone(),
            secret: Secret::new(b"hunter2"),
        })
        .expect("password completes the flow");
    assert!(
        matches!(done, AuthProgress::Established),
        "the flow finishes Established after the password"
    );
}

#[test]
fn challenge_emits_one_interaction_id() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let group = vault.begin();
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"g"),
        })
        .expect("advance");
    let AuthProgress::Challenge(username) = username else {
        panic!("expected username challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"u"),
        })
        .expect("advance");
    let AuthProgress::Challenge(password) = password else {
        panic!("expected password challenge");
    };

    // Every challenge carries EXACTLY ONE InteractionId, and each one is fresh and
    // distinct. A mutant that reuses an id (or emits the same id for two prompts)
    // must fail here.
    assert_ne!(
        group.interaction_id, username.interaction_id,
        "group and username must use distinct InteractionIds"
    );
    assert_ne!(
        username.interaction_id, password.interaction_id,
        "username and password must use distinct InteractionIds"
    );
    assert_ne!(
        group.interaction_id, password.interaction_id,
        "a challenge must never reuse an earlier InteractionId"
    );
}

#[test]
fn stale_interaction_is_rejected() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock.clone(), Duration::from_secs(30));

    let group = vault.begin();
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"g"),
        })
        .expect("advance");
    let AuthProgress::Challenge(_username) = username else {
        panic!("expected username challenge");
    };

    // An InteractionId this vault never issued is stale and must be rejected.
    let other = AuthInteraction::new(clock, Duration::from_secs(30));
    let foreign_id = other.begin().interaction_id;

    let err = vault
        .respond(AuthResponse {
            interaction_id: foreign_id,
            secret: Secret::new(b"x"),
        })
        .expect_err("a stale id from another session must be rejected");
    assert!(
        matches!(err, AuthError::StaleInteraction),
        "an unknown InteractionId surfaces as StaleInteraction"
    );
}

#[test]
fn duplicate_response_is_rejected() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let group = vault.begin();
    vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"g"),
        })
        .expect("the first use of the id is accepted");

    // Re-using the SAME (already consumed) InteractionId must be rejected: ids are
    // single-use. A mutant that reuses an id must fail here.
    let err = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"g2"),
        })
        .expect_err("a consumed id cannot be reused");
    assert!(
        matches!(err, AuthError::DuplicateInteraction),
        "re-answering a consumed InteractionId surfaces as DuplicateInteraction"
    );
}

#[test]
fn expired_response_is_rejected() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock.clone(), Duration::from_secs(30));

    let group = vault.begin();

    // Advance the injected (paused) clock past the prompt deadline. No real time
    // elapses and nothing sleeps.
    clock.advance(31_000);

    let err = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"too-late"),
        })
        .expect_err("a response past the deadline must be rejected");
    assert!(
        matches!(err, AuthError::ExpiredInteraction),
        "a response after the prompt deadline surfaces as ExpiredInteraction"
    );
}

#[test]
fn stop_revokes_prompt() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let group = vault.begin();

    let revoked = vault.stop();
    assert!(
        revoked.contains(&group.interaction_id),
        "stop must revoke the pending prompt's InteractionId"
    );
    assert!(
        vault.is_stopped(),
        "the vault must record that it is stopped"
    );

    // The revoked prompt can no longer be answered. A mutant that does not clear
    // the prompt on Stop must fail here.
    let err = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id,
            secret: Secret::new(b"x"),
        })
        .expect_err("a revoked prompt cannot be answered");
    assert!(
        matches!(err, AuthError::Stopped),
        "answering after Stop surfaces as Stopped"
    );
}

#[test]
fn secret_zeroized_after_send() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let password_id = run_to_password(&mut vault);

    let password = Secret::new(b"hunter2-secret");
    let password_handle = password.clone();
    let done = vault
        .respond(AuthResponse {
            interaction_id: password_id,
            secret: password,
        })
        .expect("deposit the password");
    assert!(matches!(done, AuthProgress::Established));
    assert!(
        !password_handle.is_zeroed(),
        "the secret is still held pending before send"
    );

    vault.send_secret();
    assert!(
        password_handle.is_zeroed(),
        "the password buffer must be wiped (zeroized) after send"
    );
}

#[test]
fn secret_zeroized_on_stop() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let password_id = run_to_password(&mut vault);

    let password = Secret::new(b"hunter2-secret");
    let password_handle = password.clone();
    let done = vault
        .respond(AuthResponse {
            interaction_id: password_id,
            secret: password,
        })
        .expect("deposit the password");
    assert!(matches!(done, AuthProgress::Established));
    assert!(
        !password_handle.is_zeroed(),
        "the secret is still held pending before stop"
    );

    vault.stop();
    assert!(
        password_handle.is_zeroed(),
        "the password buffer must be wiped (zeroized) on stop"
    );
}

#[test]
fn secret_absent_from_debug_trace_and_error() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    let group = vault.begin();
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"vpn-group"),
        })
        .expect("advance");
    let AuthProgress::Challenge(username) = username else {
        panic!("expected username challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"alice"),
        })
        .expect("advance");
    let AuthProgress::Challenge(password_challenge) = password else {
        panic!("expected password challenge");
    };

    let password_bytes: &[u8] = b"hunter2-very-secret";
    let password = Secret::new(password_bytes);
    let _handle = password.clone();
    let done = vault
        .respond(AuthResponse {
            interaction_id: password_challenge.interaction_id.clone(),
            secret: password,
        })
        .expect("deposit the password");
    assert!(matches!(done, AuthProgress::Established));

    // The vault now holds the password secret. Its Debug/trace output must NOT
    // contain it.
    let vault_debug = format!("{:?}", vault);
    assert!(
        !vault_debug.contains("hunter2-very-secret"),
        "the vault Debug output must not leak the secret"
    );

    // A challenge's Debug output must not contain the secret either.
    let challenge_debug = format!("{:?}", password_challenge);
    assert!(
        !challenge_debug.contains("hunter2-very-secret"),
        "the challenge Debug output must not leak the secret"
    );

    // Typed errors must never carry the secret.
    let err_debug = format!("{:?}", AuthError::ExpiredInteraction);
    assert!(
        !err_debug.contains("hunter2-very-secret"),
        "error Debug output must not leak the secret"
    );
}

#[test]
fn unsupported_sso_or_hostscan_is_typed_error() {
    let clock = Arc::new(FakeClock::at(0));
    let vault = AuthInteraction::new(clock, Duration::from_secs(30));

    // SSO is not supported by the MVP: it must surface as a typed error, never a
    // silent fallback or a panic.
    let err = vault
        .reject_unsupported(AuthChallengeKind::Sso)
        .expect_err("SSO must be rejected");
    assert!(
        matches!(err, AuthError::Unsupported(AuthChallengeKind::Sso)),
        "an SSO offer surfaces as a typed Unsupported error"
    );

    // HostScan is likewise unsupported.
    let err = vault
        .reject_unsupported(AuthChallengeKind::HostScan)
        .expect_err("HostScan must be rejected");
    assert!(
        matches!(err, AuthError::Unsupported(AuthChallengeKind::HostScan)),
        "a HostScan offer surfaces as a typed Unsupported error"
    );
}