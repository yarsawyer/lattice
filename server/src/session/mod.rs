use crate::ws::protocol::{ServerEvent, SessionRole};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc::Sender};

pub const SESSION_TTL: Duration = Duration::from_secs(60 * 30);
pub const RELAY_QUEUE_CAPACITY: usize = 64;
pub const REPLAY_CACHE_CAPACITY: usize = 256;

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
                alice: None,
                bob: None,
                replay_cache: ReplayCache::default(),
            },
        );
        Ok(expires_at)
    }

    pub async fn join(
        &self,
        session_id: &str,
        role: SessionRole,
        sender: Sender<ServerEvent>,
    ) -> Result<JoinResult, &'static str> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return Err("unknown session");
        };

        if session.expires_at <= Instant::now() {
            sessions.remove(session_id);
            return Err("session expired");
        }

        let slot = match role {
            SessionRole::Alice => &mut session.alice,
            SessionRole::Bob => &mut session.bob,
        };

        if slot.is_some() {
            return Err("role already connected");
        }

        *slot = Some(sender);

        let peer_joined = session.alice.is_some() && session.bob.is_some();
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
        event: ServerEvent,
    ) -> Result<(), &'static str> {
        let peer = {
            let sessions = self.sessions.read().await;
            let Some(session) = sessions.get(session_id) else {
                return Err("unknown session");
            };

            match from {
                SessionRole::Alice => session.bob.clone(),
                SessionRole::Bob => session.alice.clone(),
            }
        };

        let Some(peer) = peer else {
            return Err("peer not connected");
        };

        peer.send(event).await.map_err(|_| "peer disconnected")
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
                SessionRole::Alice => session.alice.clone(),
                SessionRole::Bob => session.bob.clone(),
            }
        };

        let Some(target) = target else {
            return Err("target not connected");
        };

        target.send(event).await.map_err(|_| "target disconnected")
    }

    pub async fn disconnect(&self, session_id: &str, role: SessionRole) {
        let (peer, remove_session) = {
            let mut sessions = self.sessions.write().await;
            let Some(session) = sessions.get_mut(session_id) else {
                return;
            };

            match role {
                SessionRole::Alice => session.alice = None,
                SessionRole::Bob => session.bob = None,
            }

            let peer = match role {
                SessionRole::Alice => session.bob.clone(),
                SessionRole::Bob => session.alice.clone(),
            };
            let remove_session = session.alice.is_none() && session.bob.is_none();
            (peer, remove_session)
        };

        if let Some(peer) = peer {
            let _ = peer.send(ServerEvent::PeerLeft).await;
        }

        if remove_session {
            self.sessions.write().await.remove(session_id);
        }
    }

    pub async fn close_session(&self, session_id: &str) -> Result<(), &'static str> {
        let Some(session) = self.sessions.write().await.remove(session_id) else {
            return Err("unknown session");
        };

        if let Some(alice) = session.alice {
            let _ = alice.send(ServerEvent::SessionExpired).await;
        }
        if let Some(bob) = session.bob {
            let _ = bob.send(ServerEvent::SessionExpired).await;
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
            if let Some(alice) = session.alice {
                let _ = alice.send(ServerEvent::SessionExpired).await;
            }
            if let Some(bob) = session.bob {
                let _ = bob.send(ServerEvent::SessionExpired).await;
            }
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
    alice: Option<Sender<ServerEvent>>,
    bob: Option<Sender<ServerEvent>>,
    replay_cache: ReplayCache,
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

        if self.order.len() > REPLAY_CACHE_CAPACITY {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn sink() -> mpsc::Sender<ServerEvent> {
        let (tx, _rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        tx
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

        registry.disconnect(&session_id, SessionRole::Alice).await;
        assert!(registry.sessions.read().await.contains_key(&session_id));

        registry.disconnect(&session_id, SessionRole::Bob).await;
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
}
