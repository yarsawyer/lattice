mod limits;
mod session;
mod ws;

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use limits::RateLimiter;
use serde::{Deserialize, Serialize};
use session::{RELAY_QUEUE_CAPACITY, SessionRegistry};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
use tokio::{sync::mpsc, time::sleep};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::{error, info};
use ws::protocol::{ClientEvent, ServerEvent, SessionRole};

const MAX_WS_TEXT_BYTES: usize = 32 * 1024;
const MAX_FIELD_BASE64_BYTES: usize = 12 * 1024;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CREATE_SESSION_LIMIT: usize = 20;
const WS_FRAME_LIMIT: usize = 240;

#[derive(Clone)]
struct AppState {
    registry: SessionRegistry,
    limiter: RateLimiter,
    client_dist_dir: PathBuf,
    trust_proxy_headers: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionRequest {
    session_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    session_id: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct JoinQuery {
    sid: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let state = AppState {
        registry: SessionRegistry::new(),
        limiter: RateLimiter::new(),
        client_dist_dir: PathBuf::from("client/dist"),
        trust_proxy_headers: std::env::var("LATTICE_TRUST_PROXY_HEADERS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false),
    };

    spawn_sweeper(state.registry.clone());

    let app = Router::new()
        .route("/", get(root_redirect))
        .route("/join", get(join_page))
        .route("/healthz", get(healthz))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{id}/close", post(close_session))
        .route("/api/v1/ws", get(ws_handler))
        .nest_service("/assets", ServeDir::new("client/dist/assets"))
        .nest_service("/generated", ServeDir::new("client/src/generated"))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let host = std::env::var("LATTICE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("LATTICE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap();
    info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

fn spawn_sweeper(registry: SessionRegistry) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;
            registry.sweep_expired().await;
        }
    });
}

async fn create_session(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(payload): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&headers, addr, state.trust_proxy_headers);
    if !state
        .limiter
        .check(
            format!("create-session:{client_ip}"),
            CREATE_SESSION_LIMIT,
            RATE_LIMIT_WINDOW,
        )
        .await
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()));
    }

    if !is_valid_session_id(&payload.session_id) {
        return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
    }

    let expires_at = state
        .registry
        .create_session(payload.session_id.clone())
        .await
        .map_err(|err| (StatusCode::CONFLICT, err.to_string()))?;

    let expires_in_seconds = expires_at
        .saturating_duration_since(std::time::Instant::now())
        .as_secs();

    Ok(Json(CreateSessionResponse {
        session_id: payload.session_id,
        expires_in_seconds,
    }))
}

async fn root_redirect() -> impl IntoResponse {
    axum::response::Redirect::temporary("/join")
}

async fn healthz() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn join_page(
    Query(query): Query<JoinQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(sid) = query.sid.as_deref() {
        if !is_valid_session_id(sid) {
            return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
        }
    }

    let html_path = state.client_dist_dir.join("index.html");
    let html = tokio::fs::read_to_string(&html_path)
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "client build not found".into()))?;

    Ok((
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                ),
            ),
            (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                HeaderValue::from_static("same-origin"),
            ),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        html,
    ))
}

async fn close_session(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !is_valid_session_id(&session_id) {
        return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
    }

    state
        .registry
        .close_session(&session_id)
        .await
        .map_err(|err| (StatusCode::NOT_FOUND, err.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn ws_handler(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, addr, state.trust_proxy_headers);
    ws.max_message_size(MAX_WS_TEXT_BYTES)
        .on_upgrade(move |socket| handle_socket(state, client_ip, socket))
}

async fn handle_socket(state: AppState, client_ip: IpAddr, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ServerEvent>(RELAY_QUEUE_CAPACITY);

    let send_task = tokio::spawn(async move {
        while let Some(event) = outgoing_rx.recv().await {
            let payload = match serde_json::to_string(&event) {
                Ok(payload) => payload,
                Err(err) => {
                    error!("failed to serialize server event: {err}");
                    continue;
                }
            };

            if sender.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    });

    let Some(Ok(Message::Text(join_text))) = receiver.next().await else {
        send_task.abort();
        return;
    };

    let join_event: ClientEvent = match serde_json::from_str(&join_text) {
        Ok(event) => event,
        Err(_) => {
            let _ = outgoing_tx.try_send(ServerEvent::Error {
                message: "expected join_session frame".into(),
            });
            send_task.abort();
            return;
        }
    };

    let ClientEvent::JoinSession { session_id, role } = join_event else {
        let _ = outgoing_tx.try_send(ServerEvent::Error {
            message: "expected join_session frame".into(),
        });
        send_task.abort();
        return;
    };

    let join_result = match state
        .registry
        .join(&session_id, role, outgoing_tx.clone())
        .await
    {
        Ok(result) => result,
        Err(err) => {
            let _ = outgoing_tx.try_send(ServerEvent::Error {
                message: err.to_string(),
            });
            send_task.abort();
            return;
        }
    };

    let _ = outgoing_tx.try_send(ServerEvent::JoinedSession {
        role,
        expires_in_seconds: join_result.expires_in_seconds,
    });

    if join_result.peer_joined {
        let _ = state
            .registry
            .notify_role(&session_id, SessionRole::Alice, ServerEvent::PeerJoined)
            .await;
        let _ = state
            .registry
            .notify_role(&session_id, SessionRole::Bob, ServerEvent::PeerJoined)
            .await;
    }

    while let Some(message) = receiver.next().await {
        let Ok(message) = message else {
            break;
        };

        match message {
            Message::Text(text) => {
                if text.len() > MAX_WS_TEXT_BYTES
                    || !state
                        .limiter
                        .check(
                            format!("ws-frame:{client_ip}"),
                            WS_FRAME_LIMIT,
                            RATE_LIMIT_WINDOW,
                        )
                        .await
                {
                    let _ = outgoing_tx.try_send(ServerEvent::Error {
                        message: if text.len() > MAX_WS_TEXT_BYTES {
                            "frame too large".into()
                        } else {
                            "rate limit exceeded".into()
                        },
                    });
                    continue;
                }

                if let Err(err) = route_message(&state, &session_id, role, &text).await {
                    let _ = outgoing_tx.try_send(ServerEvent::Error {
                        message: err.to_string(),
                    });
                }
            }
            Message::Close(_) => break,
            Message::Ping(payload) => {
                let _ = outgoing_tx.try_send(ServerEvent::Pong);
                if !payload.is_empty() {
                    let _ = outgoing_tx.try_send(ServerEvent::Error {
                        message: "binary ping payloads are ignored".into(),
                    });
                }
            }
            _ => {}
        }
    }

    state.registry.disconnect(&session_id, role).await;
    send_task.abort();
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr, trust_proxy_headers: bool) -> IpAddr {
    if trust_proxy_headers {
        if let Some(ip) = forwarded_ip(headers.get("x-forwarded-for")) {
            return ip;
        }

        if let Some(ip) = forwarded_ip(headers.get("x-real-ip")) {
            return ip;
        }
    }

    addr.ip()
}

fn forwarded_ip(value: Option<&HeaderValue>) -> Option<IpAddr> {
    let value = value?.to_str().ok()?;
    let candidate = value.split(',').next()?.trim();
    candidate.parse().ok()
}

async fn route_message(
    state: &AppState,
    session_id: &str,
    role: SessionRole,
    payload: &str,
) -> Result<(), &'static str> {
    let event: ClientEvent = serde_json::from_str(payload).map_err(|_| "invalid JSON frame")?;
    validate_event_size(&event)?;
    if let Some(fingerprint) = frame_fingerprint(role, &event) {
        if state
            .registry
            .check_and_record_fingerprint(session_id, fingerprint)
            .await?
        {
            return Ok(());
        }
    }

    match event {
        ClientEvent::JoinSession { .. } => Err("session already joined"),
        ClientEvent::HandshakeOffer {
            offer_x25519_public,
            alice_nonce,
        } => state
            .registry
            .relay_to_peer(
                session_id,
                role,
                ServerEvent::RelayHandshakeOffer {
                    offer_x25519_public,
                    alice_nonce,
                },
            )
            .await,
        ClientEvent::HandshakeAnswer {
            bob_mlkem_public,
            bob_x25519_public,
            bob_nonce,
        } => state
            .registry
            .relay_to_peer(
                session_id,
                role,
                ServerEvent::RelayHandshakeAnswer {
                    bob_mlkem_public,
                    bob_x25519_public,
                    bob_nonce,
                },
            )
            .await,
        ClientEvent::HandshakeFinish { kem_ciphertext, mac } => state
            .registry
            .relay_to_peer(
                session_id,
                role,
                ServerEvent::RelayHandshakeFinish {
                    kem_ciphertext,
                    mac,
                },
            )
            .await,
        ClientEvent::HandshakeConfirm { mac } => state
            .registry
            .relay_to_peer(
                session_id,
                role,
                ServerEvent::RelayHandshakeConfirm { mac },
            )
            .await,
        ClientEvent::ChatMessage {
            seq,
            nonce,
            ciphertext,
        } => state
            .registry
            .relay_to_peer(
                session_id,
                role,
                ServerEvent::RelayChatMessage {
                    seq,
                    nonce,
                    ciphertext,
                },
            )
            .await,
        ClientEvent::ChatAck { seq } => state
            .registry
            .relay_to_peer(session_id, role, ServerEvent::RelayChatAck { seq })
            .await,
        ClientEvent::LeaveSession => {
            state.registry.disconnect(session_id, role).await;
            Ok(())
        }
        ClientEvent::Ping => state
            .registry
            .notify_role(session_id, role, ServerEvent::Pong)
            .await,
    }
}

fn is_valid_session_id(session_id: &str) -> bool {
    session_id.len() == 64 && session_id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_event_size(event: &ClientEvent) -> Result<(), &'static str> {
    match event {
        ClientEvent::JoinSession { session_id, .. } => {
            if !is_valid_session_id(session_id) {
                return Err("invalid session id");
            }
        }
        ClientEvent::HandshakeOffer {
            offer_x25519_public,
            alice_nonce,
        } => {
            ensure_field_limit(offer_x25519_public)?;
            ensure_field_limit(alice_nonce)?;
        }
        ClientEvent::HandshakeAnswer {
            bob_mlkem_public,
            bob_x25519_public,
            bob_nonce,
        } => {
            ensure_field_limit(bob_mlkem_public)?;
            ensure_field_limit(bob_x25519_public)?;
            ensure_field_limit(bob_nonce)?;
        }
        ClientEvent::HandshakeFinish { kem_ciphertext, mac } => {
            ensure_field_limit(kem_ciphertext)?;
            ensure_field_limit(mac)?;
        }
        ClientEvent::HandshakeConfirm { mac } => ensure_field_limit(mac)?,
        ClientEvent::ChatMessage {
            nonce,
            ciphertext,
            ..
        } => {
            ensure_field_limit(nonce)?;
            ensure_field_limit(ciphertext)?;
        }
        ClientEvent::ChatAck { .. } | ClientEvent::LeaveSession | ClientEvent::Ping => {}
    }

    Ok(())
}

fn ensure_field_limit(value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_FIELD_BASE64_BYTES {
        Err("field too large")
    } else {
        Ok(())
    }
}

fn frame_fingerprint(role: SessionRole, event: &ClientEvent) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    role.hash(&mut hasher);

    match event {
        ClientEvent::HandshakeOffer {
            offer_x25519_public,
            alice_nonce,
        } => {
            "handshake_offer".hash(&mut hasher);
            offer_x25519_public.hash(&mut hasher);
            alice_nonce.hash(&mut hasher);
        }
        ClientEvent::HandshakeAnswer {
            bob_mlkem_public,
            bob_x25519_public,
            bob_nonce,
        } => {
            "handshake_answer".hash(&mut hasher);
            bob_mlkem_public.hash(&mut hasher);
            bob_x25519_public.hash(&mut hasher);
            bob_nonce.hash(&mut hasher);
        }
        ClientEvent::HandshakeFinish { kem_ciphertext, mac } => {
            "handshake_finish".hash(&mut hasher);
            kem_ciphertext.hash(&mut hasher);
            mac.hash(&mut hasher);
        }
        ClientEvent::HandshakeConfirm { mac } => {
            "handshake_confirm".hash(&mut hasher);
            mac.hash(&mut hasher);
        }
        ClientEvent::ChatMessage {
            seq,
            nonce,
            ciphertext,
        } => {
            "chat_message".hash(&mut hasher);
            seq.hash(&mut hasher);
            nonce.hash(&mut hasher);
            ciphertext.hash(&mut hasher);
        }
        ClientEvent::ChatAck { seq } => {
            "chat_ack".hash(&mut hasher);
            seq.hash(&mut hasher);
        }
        ClientEvent::JoinSession { .. } | ClientEvent::LeaveSession | ClientEvent::Ping => {
            return None;
        }
    }

    Some(hasher.finish())
}
