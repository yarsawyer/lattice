use crate::ws::protocol::{RelayPayload, ServerEvent, SessionRole};
use lattice_crypto::{SessionRole as CryptoSessionRole, resume_mac, resume_verifier};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc::Sender};

pub const SESSION_TTL: Duration = Duration::from_secs(60 * 30);
pub const RELAY_QUEUE_CAPACITY: usize = 64;
pub const REPLAY_CACHE_CAPACITY: usize = 256;
pub const RESUME_GRACE_PERIOD: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, session_id: String) -> Result<Instant, &'static str> {
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(&session_id) {
            return Err("session already exists");
        }

        let expires_at = Instant::now() + SESSION_TTL;
        sessions.insert(
            session_id.clone(),
            SessionState {
                session_id,
                expires_at,
                alice: RoleState::default(),
                bob: RoleState::default(),
                replay_cache: ReplayCache::default(),
            },
        );
        Ok(expires_at)
    }

    pub async fn join(
        &self,
        session_id: &str,
        role: SessionRole,
        sender: Sender<RelayPayload>,
    ) -> Result<JoinResult, &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        if session.expires_at <= Instant::now() {
            sessions.remove(session_id);
            return Err("session expired");
        }

        let slot = role_state_mut(session, role);

        if slot.sender.is_some() || slot.disconnected_at.is_some() {
            return Err("role already connected");
        }

        slot.sender = Some(sender);
        slot.challenge_nonce = None;

        let peer_joined = session.alice.sender.is_some() && session.bob.sender.is_some();
        Ok(JoinResult {
            expires_in_seconds: session
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_secs(),
            peer_joined,
        })
    }

    pub async fn relay_to_peer(
        &self,
        session_id: &str,
        from: SessionRole,
        payload: RelayPayload,
    ) -> Result<(), &'static str> {
        let peer = {
            let sessions = self.sessions.read().await;
            let Some(session) = sessions.get(session_id) else {
                return Err("unknown session");
            };

            match from {
                SessionRole::Alice => session.bob.sender.clone(),
                SessionRole::Bob => session.alice.sender.clone(),
            }
        };

        let Some(peer) = peer else {
            return Err("peer not connected");
        };

        peer.send(payload).await.map_err(|_| "peer disconnected")
    }

    pub async fn notify_role(
        &self,
        session_id: &str,
        role: SessionRole,
        event: ServerEvent,
    ) -> Result<(), &'static str> {
        let target = {
            let sessions = self.sessions.read().await;
            let Some(session) = sessions.get(session_id) else {
                return Err("unknown session");
            };

            match role {
                SessionRole::Alice => session.alice.sender.clone(),
                SessionRole::Bob => session.bob.sender.clone(),
            }
        };

        let Some(target) = target else {
            return Err("target not connected");
        };

        target
            .send(RelayPayload::Event(event))
            .await
            .map_err(|_| "target disconnected")
    }

    pub async fn register_resume_verifier(
        &self,
        session_id: &str,
        role: SessionRole,
        verifier: [u8; 32],
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        role_state_mut(session, role).resume_verifier = Some(verifier);
        Ok(())
    }

    pub async fn begin_resume(
        &self,
        session_id: &str,
        role: SessionRole,
        challenge_nonce: [u8; 32],
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        if session.expires_at <= Instant::now() {
            sessions.remove(session_id);
            return Err("session expired");
        }

        let slot = role_state_mut(session, role);
        if slot.sender.is_some() {
            return Err("role already connected");
        }
        if slot.disconnected_at.is_none() {
            return Err("role not awaiting resume");
        }
        if slot.resume_verifier.is_none() {
            return Err("resume not registered");
        }

        slot.challenge_nonce = Some(challenge_nonce);
        Ok(())
    }

    pub async fn complete_resume(
        &self,
        session_id: &str,
        role: SessionRole,
        sender: Sender<RelayPayload>,
        resume_key: &[u8],
        mac: &[u8],
    ) -> Result<bool, &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        let peer_connected = {
            let slot = role_state_mut(session, role);
            let Some(stored_verifier) = slot.resume_verifier else {
                return Err("resume not registered");
            };
            let Some(challenge_nonce) = slot.challenge_nonce.take() else {
                return Err("resume challenge missing");
            };
            if slot.disconnected_at.is_none() || slot.sender.is_some() {
                return Err("role not awaiting resume");
            }

            let verifier = resume_verifier(resume_key).map_err(|_| "resume verification failed")?;
            if verifier != stored_verifier {
                return Err("resume verification failed");
            }

            let expected_mac = resume_mac(
                resume_key,
                &challenge_nonce,
                session_id,
                to_crypto_role(role),
            )
            .map_err(|_| "resume verification failed")?;
            if expected_mac != mac {
                return Err("resume verification failed");
            }

            slot.sender = Some(sender);
            slot.disconnected_at = None;

            peer_state(session, role).sender.is_some()
        };

        Ok(peer_connected)
    }

    pub async fn transport_disconnect(
        &self,
        session_id: &str,
        role: SessionRole,
    ) -> Option<Instant> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)?;

        let slot = role_state_mut(session, role);
        slot.sender.as_ref()?;

        slot.sender = None;
        slot.challenge_nonce = None;

        if slot.resume_verifier.is_some() {
            let disconnected_at = Instant::now();
            slot.disconnected_at = Some(disconnected_at);
            return Some(disconnected_at);
        }

        drop(sessions);
        self.terminate_with_peer_left(session_id, role).await;
        None
    }

    pub async fn expire_disconnect(
        &self,
        session_id: &str,
        role: SessionRole,
        disconnected_at: Instant,
    ) {
        let should_terminate = {
            let sessions = self.sessions.read().await;
            let Some(session) = sessions.get(session_id) else {
                return;
            };

            role_state(session, role).disconnected_at == Some(disconnected_at)
        };

        if should_terminate {
            self.terminate_with_peer_left(session_id, role).await;
        }
    }

    pub async fn disconnect(&self, session_id: &str, role: SessionRole) {
        self.terminate_with_peer_left(session_id, role).await;
    }

    pub async fn close_session(&self, session_id: &str) -> Result<(), &'static str> {
        let Some(session) = self.sessions.write().await.remove(session_id) else {
            return Err("unknown session");
        };

        if let Some(alice) = session.alice.sender {
            let _ = alice
                .send(RelayPayload::Event(ServerEvent::SessionExpired))
                .await;
        }
        if let Some(bob) = session.bob.sender {
            let _ = bob
                .send(RelayPayload::Event(ServerEvent::SessionExpired))
                .await;
        }

        Ok(())
    }

    pub async fn check_and_record_fingerprint(
        &self,
        session_id: &str,
        fingerprint: u64,
    ) -> Result<bool, &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        Ok(session.replay_cache.insert(fingerprint))
    }

    pub async fn sweep_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let expired_ids = sessions
            .iter()
            .filter_map(|(id, session)| (session.expires_at <= now).then_some(id.clone()))
            .collect::<Vec<_>>();

        let mut expired_sessions = Vec::new();
        for id in expired_ids {
            if let Some(session) = sessions.remove(&id) {
                expired_sessions.push(session);
            }
        }
        drop(sessions);

        for session in expired_sessions {
            if let Some(alice) = session.alice.sender {
                let _ = alice
                    .send(RelayPayload::Event(ServerEvent::SessionExpired))
                    .await;
            }
            if let Some(bob) = session.bob.sender {
                let _ = bob
                    .send(RelayPayload::Event(ServerEvent::SessionExpired))
                    .await;
            }
        }
    }

    async fn terminate_with_peer_left(&self, session_id: &str, departed: SessionRole) {
        let peer = {
            let mut sessions = self.sessions.write().await;
            let Some(session) = sessions.remove(session_id) else {
                return;
            };

            match departed {
                SessionRole::Alice => session.bob.sender,
                SessionRole::Bob => session.alice.sender,
            }
        };

        if let Some(peer) = peer {
            let _ = peer.send(RelayPayload::Event(ServerEvent::PeerLeft)).await;
        }
    }
}

#[derive(Debug)]
pub struct JoinResult {
    pub expires_in_seconds: u64,
    pub peer_joined: bool,
}

struct SessionState {
    #[allow(dead_code)]
    session_id: String,
    expires_at: Instant,
    alice: RoleState,
    bob: RoleState,
    replay_cache: ReplayCache,
}

#[derive(Default)]
struct RoleState {
    sender: Option<Sender<RelayPayload>>,
    resume_verifier: Option<[u8; 32]>,
    disconnected_at: Option<Instant>,
    challenge_nonce: Option<[u8; 32]>,
}

#[derive(Default)]
struct ReplayCache {
    order: VecDeque<u64>,
    seen: HashSet<u64>,
}

impl ReplayCache {
    fn insert(&mut self, fingerprint: u64) -> bool {
        if self.seen.contains(&fingerprint) {
            return true;
        }

        self.order.push_back(fingerprint);
        self.seen.insert(fingerprint);

        if self.order.len() > REPLAY_CACHE_CAPACITY
            && let Some(expired) = self.order.pop_front()
        {
            self.seen.remove(&expired);
        }

        false
    }
}

fn role_state(session: &SessionState, role: SessionRole) -> &RoleState {
    match role {
        SessionRole::Alice => &session.alice,
        SessionRole::Bob => &session.bob,
    }
}

fn role_state_mut(session: &mut SessionState, role: SessionRole) -> &mut RoleState {
    match role {
        SessionRole::Alice => &mut session.alice,
        SessionRole::Bob => &mut session.bob,
    }
}

fn peer_state(session: &SessionState, role: SessionRole) -> &RoleState {
    match role {
        SessionRole::Alice => &session.bob,
        SessionRole::Bob => &session.alice,
    }
}

fn to_crypto_role(role: SessionRole) -> CryptoSessionRole {
    match role {
        SessionRole::Alice => CryptoSessionRole::Alice,
        SessionRole::Bob => CryptoSessionRole::Bob,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{Duration as TokioDuration, timeout};

    fn sink() -> mpsc::Sender<RelayPayload> {
        let (tx, _rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        tx
    }

    fn channel() -> (mpsc::Sender<RelayPayload>, mpsc::Receiver<RelayPayload>) {
        mpsc::channel(RELAY_QUEUE_CAPACITY)
    }

    #[tokio::test]
    async fn creates_session() {
        let registry = SessionRegistry::new();
        let created = registry
            .create_session("a".repeat(64))
            .await
            .expect("session should be created");
        assert!(created > Instant::now());
        assert_eq!(registry.sessions.read().await.len(), 1);
    }

    #[tokio::test]
    async fn joins_valid_session() {
        let registry = SessionRegistry::new();
        let session_id = "b".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let alice = registry
            .join(&session_id, SessionRole::Alice, sink())
            .await
            .expect("alice should join");
        assert!(!alice.peer_joined);

        let bob = registry
            .join(&session_id, SessionRole::Bob, sink())
            .await
            .expect("bob should join");
        assert!(bob.peer_joined);
    }

    #[tokio::test]
    async fn rejects_unknown_or_expired_session() {
        let registry = SessionRegistry::new();
        let missing = registry.join("missing", SessionRole::Alice, sink()).await;
        assert_eq!(missing.unwrap_err(), "unknown session");

        let session_id = "c".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();
        {
            let mut sessions = registry.sessions.write().await;
            let session = sessions.get_mut(&session_id).unwrap();
            session.expires_at = Instant::now() - Duration::from_secs(1);
        }

        let expired = registry.join(&session_id, SessionRole::Alice, sink()).await;
        assert_eq!(expired.unwrap_err(), "session expired");
    }

    #[tokio::test]
    async fn rejects_duplicate_or_third_participant() {
        let registry = SessionRegistry::new();
        let session_id = "d".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        registry
            .join(&session_id, SessionRole::Alice, sink())
            .await
            .unwrap();
        let duplicate = registry.join(&session_id, SessionRole::Alice, sink()).await;
        assert_eq!(duplicate.unwrap_err(), "role already connected");
    }

    #[tokio::test]
    async fn sweeps_expired_sessions() {
        let registry = SessionRegistry::new();
        let session_id = "e".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();
        {
            let mut sessions = registry.sessions.write().await;
            let session = sessions.get_mut(&session_id).unwrap();
            session.expires_at = Instant::now() - Duration::from_secs(1);
        }

        registry.sweep_expired().await;
        assert!(!registry.sessions.read().await.contains_key(&session_id));
    }

    #[tokio::test]
    async fn cleans_up_after_disconnect() {
        let registry = SessionRegistry::new();
        let session_id = "f".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();
        registry
            .join(&session_id, SessionRole::Alice, sink())
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, sink())
            .await
            .unwrap();

        let disconnected = registry
            .transport_disconnect(&session_id, SessionRole::Alice)
            .await;
        assert!(disconnected.is_none());
        assert!(!registry.sessions.read().await.contains_key(&session_id));
    }

    #[tokio::test]
    async fn deduplicates_replayed_fingerprints() {
        let registry = SessionRegistry::new();
        let session_id = "1".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        assert!(
            !registry
                .check_and_record_fingerprint(&session_id, 42)
                .await
                .unwrap()
        );
        assert!(
            registry
                .check_and_record_fingerprint(&session_id, 42)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn relays_binary_payloads_to_peer() {
        let registry = SessionRegistry::new();
        let session_id = "2".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let (alice_tx, _alice_rx) = channel();
        let (bob_tx, mut bob_rx) = channel();

        registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();

        registry
            .relay_to_peer(
                &session_id,
                SessionRole::Alice,
                RelayPayload::Binary(vec![1, 2, 3, 4]),
            )
            .await
            .unwrap();

        let Some(RelayPayload::Binary(bytes)) = bob_rx.recv().await else {
            panic!("expected binary relay payload");
        };
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn keeps_session_alive_during_resume_grace_period() {
        let registry = SessionRegistry::new();
        let session_id = "3".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let resume_key = [7_u8; 32];
        let verifier = resume_verifier(&resume_key).unwrap();
        let (alice_tx, _alice_rx) = channel();
        let (bob_tx, mut bob_rx) = channel();

        registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();
        registry
            .register_resume_verifier(&session_id, SessionRole::Alice, verifier)
            .await
            .unwrap();

        let disconnected_at = registry
            .transport_disconnect(&session_id, SessionRole::Alice)
            .await
            .expect("alice should enter resume grace");

        assert!(registry.sessions.read().await.contains_key(&session_id));
        assert!(timeout(TokioDuration::from_millis(20), bob_rx.recv())
            .await
            .is_err());

        let sessions = registry.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert!(session.alice.sender.is_none());
        assert_eq!(session.alice.disconnected_at, Some(disconnected_at));
    }

    #[tokio::test]
    async fn resumes_session_with_valid_proof() {
        let registry = SessionRegistry::new();
        let session_id = "4".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let resume_key = [8_u8; 32];
        let verifier = resume_verifier(&resume_key).unwrap();
        let challenge_nonce = [9_u8; 32];
        let mac = resume_mac(
            &resume_key,
            &challenge_nonce,
            &session_id,
            to_crypto_role(SessionRole::Alice),
        )
        .unwrap();
        let (alice_tx, _alice_rx) = channel();
        let (bob_tx, _bob_rx) = channel();
        let (resume_tx, _resume_rx) = channel();

        registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();
        registry
            .register_resume_verifier(&session_id, SessionRole::Alice, verifier)
            .await
            .unwrap();

        registry
            .transport_disconnect(&session_id, SessionRole::Alice)
            .await
            .expect("alice should enter resume grace");
        registry
            .begin_resume(&session_id, SessionRole::Alice, challenge_nonce)
            .await
            .unwrap();

        let peer_connected = registry
            .complete_resume(
                &session_id,
                SessionRole::Alice,
                resume_tx,
                &resume_key,
                &mac,
            )
            .await
            .expect("resume should succeed");

        assert!(peer_connected);

        let sessions = registry.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert!(session.alice.sender.is_some());
        assert!(session.alice.disconnected_at.is_none());
        assert!(session.alice.challenge_nonce.is_none());
    }

    #[tokio::test]
    async fn rejects_resume_with_invalid_mac() {
        let registry = SessionRegistry::new();
        let session_id = "5".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let resume_key = [10_u8; 32];
        let verifier = resume_verifier(&resume_key).unwrap();
        let challenge_nonce = [11_u8; 32];
        let (alice_tx, _alice_rx) = channel();
        let (bob_tx, _bob_rx) = channel();
        let (resume_tx, _resume_rx) = channel();

        registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();
        registry
            .register_resume_verifier(&session_id, SessionRole::Alice, verifier)
            .await
            .unwrap();

        registry
            .transport_disconnect(&session_id, SessionRole::Alice)
            .await
            .expect("alice should enter resume grace");
        registry
            .begin_resume(&session_id, SessionRole::Alice, challenge_nonce)
            .await
            .unwrap();

        let err = registry
            .complete_resume(
                &session_id,
                SessionRole::Alice,
                resume_tx,
                &resume_key,
                &[0_u8; 32],
            )
            .await
            .unwrap_err();

        assert_eq!(err, "resume verification failed");
        let sessions = registry.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert!(session.alice.sender.is_none());
        assert!(session.alice.disconnected_at.is_some());
    }

    #[tokio::test]
    async fn expires_disconnect_after_grace_period() {
        let registry = SessionRegistry::new();
        let session_id = "6".repeat(64);
        registry.create_session(session_id.clone()).await.unwrap();

        let resume_key = [12_u8; 32];
        let verifier = resume_verifier(&resume_key).unwrap();
        let (alice_tx, _alice_rx) = channel();
        let (bob_tx, mut bob_rx) = channel();

        registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();
        registry
            .register_resume_verifier(&session_id, SessionRole::Alice, verifier)
            .await
            .unwrap();

        let disconnected_at = registry
            .transport_disconnect(&session_id, SessionRole::Alice)
            .await
            .expect("alice should enter resume grace");

        registry
            .expire_disconnect(&session_id, SessionRole::Alice, disconnected_at)
            .await;

        assert!(!registry.sessions.read().await.contains_key(&session_id));
        let Some(RelayPayload::Event(ServerEvent::PeerLeft)) = bob_rx.recv().await else {
            panic!("expected peer-left after grace expiry");
        };
    }
}
