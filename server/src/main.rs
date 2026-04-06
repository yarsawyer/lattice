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
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::{SinkExt, StreamExt};
use limits::RateLimiter;
use serde::{Deserialize, Serialize};
use session::{RELAY_QUEUE_CAPACITY, RESUME_GRACE_PERIOD, SessionRegistry};
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
use ws::protocol::{ClientEvent, RelayPayload, ServerEvent, SessionRole};

const MAX_WS_TEXT_BYTES: usize = 32 * 1024;
const MAX_FIELD_BASE64_BYTES: usize = 12 * 1024;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CREATE_SESSION_LIMIT: usize = 20;
const WS_TEXT_FRAME_LIMIT: usize = 240;
const WS_BINARY_FRAME_LIMIT: usize = 10_000;

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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    if let Some(sid) = query.sid.as_deref()
        && !is_valid_session_id(sid)
    {
        return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
    }

    let html_path = state.client_dist_dir.join("index.html");
    let html = tokio::fs::read_to_string(&html_path).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "client build not found".into(),
        )
    })?;

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
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<RelayPayload>(RELAY_QUEUE_CAPACITY);

    let send_task = tokio::spawn(async move {
        while let Some(payload) = outgoing_rx.recv().await {
            let outbound = match payload {
                RelayPayload::Event(event) => match serde_json::to_string(&event) {
                    Ok(payload) => Message::Text(payload.into()),
                    Err(err) => {
                        error!("failed to serialize server event: {err}");
                        continue;
                    }
                },
                RelayPayload::Binary(bytes) => Message::Binary(bytes.into()),
            };

            if sender.send(outbound).await.is_err() {
                break;
            }
        }
    });

    let Some(Ok(Message::Text(initial_text))) = receiver.next().await else {
        send_task.abort();
        return;
    };

    let initial_event: ClientEvent = match serde_json::from_str(&initial_text) {
        Ok(event) => event,
        Err(_) => {
            let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                message: "expected join_session or resume_session frame".into(),
            }));
            send_task.abort();
            return;
        }
    };

    let (session_id, role) =
        match establish_socket_session(&state, &outgoing_tx, &mut receiver, initial_event).await {
            Ok(joined) => joined,
            Err(err) => {
                let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                    message: err.to_string(),
                }));
                send_task.abort();
                return;
            }
        };

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
                            WS_TEXT_FRAME_LIMIT,
                            RATE_LIMIT_WINDOW,
                        )
                        .await
                {
                    let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                        message: if text.len() > MAX_WS_TEXT_BYTES {
                            "frame too large".into()
                        } else {
                            "rate limit exceeded".into()
                        },
                    }));
                    continue;
                }

                if let Err(err) = route_message(&state, &session_id, role, &text).await {
                    let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                        message: err.to_string(),
                    }));
                }
            }
            Message::Binary(bytes) => {
                if bytes.len() > MAX_WS_TEXT_BYTES
                    || !state
                        .limiter
                        .check(
                            format!("ws-binary-frame:{client_ip}"),
                            WS_BINARY_FRAME_LIMIT,
                            RATE_LIMIT_WINDOW,
                        )
                        .await
                {
                    let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                        message: if bytes.len() > MAX_WS_TEXT_BYTES {
                            "frame too large".into()
                        } else {
                            "rate limit exceeded".into()
                        },
                    }));
                    continue;
                }

                if let Err(err) = state
                    .registry
                    .relay_to_peer(&session_id, role, RelayPayload::Binary(bytes.to_vec()))
                    .await
                {
                    let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                        message: err.to_string(),
                    }));
                }
            }
            Message::Close(_) => break,
            Message::Ping(payload) => {
                let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Pong));
                if !payload.is_empty() {
                    let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::Error {
                        message: "binary ping payloads are ignored".into(),
                    }));
                }
            }
            _ => {}
        }
    }

    if let Some(disconnected_at) = state.registry.transport_disconnect(&session_id, role).await {
        let registry = state.registry.clone();
        let session_id = session_id.clone();
        tokio::spawn(async move {
            sleep(RESUME_GRACE_PERIOD).await;
            registry
                .expire_disconnect(&session_id, role, disconnected_at)
                .await;
        });
    }
    send_task.abort();
}

async fn establish_socket_session(
    state: &AppState,
    outgoing_tx: &mpsc::Sender<RelayPayload>,
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    initial_event: ClientEvent,
) -> Result<(String, SessionRole), &'static str> {
    match initial_event {
        ClientEvent::JoinSession { session_id, role } => {
            let join_result = state
                .registry
                .join(&session_id, role, outgoing_tx.clone())
                .await?;

            let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::JoinedSession {
                role,
                expires_in_seconds: join_result.expires_in_seconds,
            }));

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

            Ok((session_id, role))
        }
        ClientEvent::ResumeSession { session_id, role } => {
            if !is_valid_session_id(&session_id) {
                return Err("invalid session id");
            }

            let challenge_nonce = lattice_crypto::session::generate_nonce()
                .map_err(|_| "failed to generate resume challenge")?;
            state
                .registry
                .begin_resume(&session_id, role, challenge_nonce)
                .await?;

            let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::ResumeChallenge {
                nonce: BASE64_STANDARD.encode(challenge_nonce),
            }));

            let Some(Ok(Message::Text(proof_text))) = receiver.next().await else {
                return Err("expected resume_proof frame");
            };

            let proof_event: ClientEvent =
                serde_json::from_str(&proof_text).map_err(|_| "invalid JSON frame")?;
            validate_event_size(&proof_event)?;

            let ClientEvent::ResumeProof { resume_key, mac } = proof_event else {
                return Err("expected resume_proof frame");
            };

            let resume_key = decode_base64_field(&resume_key).ok_or("invalid resume key")?;
            let mac = decode_base64_field(&mac).ok_or("invalid resume mac")?;
            let peer_connected = state
                .registry
                .complete_resume(&session_id, role, outgoing_tx.clone(), &resume_key, &mac)
                .await?;

            let _ = outgoing_tx.try_send(RelayPayload::Event(ServerEvent::ResumeAccepted));
            if peer_connected {
                let _ = state
                    .registry
                    .relay_to_peer(
                        &session_id,
                        role,
                        RelayPayload::Event(ServerEvent::PeerReconnected),
                    )
                    .await;
            }

            Ok((session_id, role))
        }
        _ => Err("expected join_session or resume_session frame"),
    }
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
    if let Some(fingerprint) = frame_fingerprint(role, &event)
        && state
            .registry
            .check_and_record_fingerprint(session_id, fingerprint)
            .await?
    {
        return Ok(());
    }

    match event {
        ClientEvent::JoinSession { .. } => Err("session already joined"),
        ClientEvent::HandshakeOffer {
            offer_x25519_public,
            alice_nonce,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayHandshakeOffer {
                        offer_x25519_public,
                        alice_nonce,
                    }),
                )
                .await
        }
        ClientEvent::HandshakeAnswer {
            bob_mlkem_public,
            bob_x25519_public,
            bob_nonce,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayHandshakeAnswer {
                        bob_mlkem_public,
                        bob_x25519_public,
                        bob_nonce,
                    }),
                )
                .await
        }
        ClientEvent::HandshakeFinish {
            kem_ciphertext,
            mac,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayHandshakeFinish {
                        kem_ciphertext,
                        mac,
                    }),
                )
                .await
        }
        ClientEvent::HandshakeConfirm { mac } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayHandshakeConfirm { mac }),
                )
                .await
        }
        ClientEvent::ChatMessage {
            seq,
            nonce,
            ciphertext,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayChatMessage {
                        seq,
                        nonce,
                        ciphertext,
                    }),
                )
                .await
        }
        ClientEvent::ChatAck { seq } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayChatAck { seq }),
                )
                .await
        }
        ClientEvent::FileOffer {
            transfer_id,
            name,
            mime_type,
            size,
            total_chunks,
            sha256,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileOffer {
                        transfer_id,
                        name,
                        mime_type,
                        size,
                        total_chunks,
                        sha256,
                    }),
                )
                .await
        }
        ClientEvent::FileAccept { transfer_id } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileAccept { transfer_id }),
                )
                .await
        }
        ClientEvent::FileReject { transfer_id } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileReject { transfer_id }),
                )
                .await
        }
        ClientEvent::FileComplete { transfer_id } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileComplete { transfer_id }),
                )
                .await
        }
        ClientEvent::FileAbort {
            transfer_id,
            reason,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileAbort {
                        transfer_id,
                        reason,
                    }),
                )
                .await
        }
        ClientEvent::FileResumeState {
            transfer_id,
            received_bitmap,
        } => {
            state
                .registry
                .relay_to_peer(
                    session_id,
                    role,
                    RelayPayload::Event(ServerEvent::RelayFileResumeState {
                        transfer_id,
                        received_bitmap,
                    }),
                )
                .await
        }
        ClientEvent::RegisterResume { verifier } => {
            let verifier = decode_hex_32(&verifier).ok_or("invalid resume verifier")?;
            state
                .registry
                .register_resume_verifier(session_id, role, verifier)
                .await
        }
        ClientEvent::ResumeSession { .. } | ClientEvent::ResumeProof { .. } => {
            Err("resume frames are only allowed during socket bootstrap")
        }
        ClientEvent::LeaveSession => {
            state.registry.disconnect(session_id, role).await;
            Ok(())
        }
        ClientEvent::Ping => {
            state
                .registry
                .notify_role(session_id, role, ServerEvent::Pong)
                .await
        }
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
        ClientEvent::HandshakeFinish {
            kem_ciphertext,
            mac,
        } => {
            ensure_field_limit(kem_ciphertext)?;
            ensure_field_limit(mac)?;
        }
        ClientEvent::HandshakeConfirm { mac } => ensure_field_limit(mac)?,
        ClientEvent::ChatMessage {
            nonce, ciphertext, ..
        } => {
            ensure_field_limit(nonce)?;
            ensure_field_limit(ciphertext)?;
        }
        ClientEvent::FileOffer {
            transfer_id,
            name,
            mime_type,
            size: _,
            total_chunks: _,
            sha256,
        } => {
            ensure_transfer_id(transfer_id)?;
            ensure_field_limit(name)?;
            ensure_field_limit(mime_type)?;
            ensure_sha256_hex(sha256)?;
        }
        ClientEvent::FileAccept { transfer_id }
        | ClientEvent::FileReject { transfer_id }
        | ClientEvent::FileComplete { transfer_id } => ensure_transfer_id(transfer_id)?,
        ClientEvent::FileAbort {
            transfer_id,
            reason,
        } => {
            ensure_transfer_id(transfer_id)?;
            ensure_field_limit(reason)?;
        }
        ClientEvent::FileResumeState {
            transfer_id,
            received_bitmap,
        } => {
            ensure_transfer_id(transfer_id)?;
            ensure_field_limit(received_bitmap)?;
        }
        ClientEvent::RegisterResume { verifier } => ensure_resume_verifier(verifier)?,
        ClientEvent::ResumeSession { session_id, .. } => {
            if !is_valid_session_id(session_id) {
                return Err("invalid session id");
            }
        }
        ClientEvent::ResumeProof { resume_key, mac } => {
            ensure_field_limit(resume_key)?;
            ensure_field_limit(mac)?;
        }
        ClientEvent::ChatAck { .. } | ClientEvent::LeaveSession | ClientEvent::Ping => {}
    }

    Ok(())
}

fn ensure_transfer_id(value: &str) -> Result<(), &'static str> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err("invalid transfer id")
    } else {
        Ok(())
    }
}

fn ensure_sha256_hex(value: &str) -> Result<(), &'static str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err("invalid sha256 digest")
    } else {
        Ok(())
    }
}

fn ensure_resume_verifier(value: &str) -> Result<(), &'static str> {
    if decode_hex_32(value).is_none() {
        Err("invalid resume verifier")
    } else {
        Ok(())
    }
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

fn decode_base64_field(value: &str) -> Option<Vec<u8>> {
    BASE64_STANDARD.decode(value).ok()
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
        ClientEvent::HandshakeFinish {
            kem_ciphertext,
            mac,
        } => {
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
        ClientEvent::FileOffer {
            transfer_id,
            name,
            mime_type,
            size,
            total_chunks,
            sha256,
        } => {
            "file_offer".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
            name.hash(&mut hasher);
            mime_type.hash(&mut hasher);
            size.hash(&mut hasher);
            total_chunks.hash(&mut hasher);
            sha256.hash(&mut hasher);
        }
        ClientEvent::FileAccept { transfer_id } => {
            "file_accept".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
        }
        ClientEvent::FileReject { transfer_id } => {
            "file_reject".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
        }
        ClientEvent::FileComplete { transfer_id } => {
            "file_complete".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
        }
        ClientEvent::FileAbort {
            transfer_id,
            reason,
        } => {
            "file_abort".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
            reason.hash(&mut hasher);
        }
        ClientEvent::FileResumeState {
            transfer_id,
            received_bitmap,
        } => {
            "file_resume_state".hash(&mut hasher);
            transfer_id.hash(&mut hasher);
            received_bitmap.hash(&mut hasher);
        }
        ClientEvent::RegisterResume { verifier } => {
            "register_resume".hash(&mut hasher);
            verifier.hash(&mut hasher);
        }
        ClientEvent::ResumeSession { .. } | ClientEvent::ResumeProof { .. } => {
            return None;
        }
        ClientEvent::JoinSession { .. } | ClientEvent::LeaveSession | ClientEvent::Ping => {
            return None;
        }
    }

    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        AppState {
            registry: SessionRegistry::new(),
            limiter: RateLimiter::new(),
            client_dist_dir: PathBuf::new(),
            trust_proxy_headers: false,
        }
    }

    #[tokio::test]
    async fn routes_file_offer_to_peer() {
        let state = test_state();
        let session_id = "a".repeat(64);
        state
            .registry
            .create_session(session_id.clone())
            .await
            .unwrap();

        let (alice_tx, _alice_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        let (bob_tx, mut bob_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);

        state
            .registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        state
            .registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();

        route_message(
            &state,
            &session_id,
            SessionRole::Alice,
            r#"{"type":"file_offer","transfer_id":"00112233445566778899aabbccddeeff","name":"notes.pdf","mime_type":"application/pdf","size":2048,"total_chunks":2,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .await
        .unwrap();

        let Some(RelayPayload::Event(ServerEvent::RelayFileOffer {
            transfer_id,
            name,
            mime_type,
            size,
            total_chunks,
            sha256,
        })) = bob_rx.recv().await
        else {
            panic!("expected relayed file offer");
        };

        assert_eq!(transfer_id, "00112233445566778899aabbccddeeff");
        assert_eq!(name, "notes.pdf");
        assert_eq!(mime_type, "application/pdf");
        assert_eq!(size, 2048);
        assert_eq!(total_chunks, 2);
        assert_eq!(
            sha256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[tokio::test]
    async fn routes_file_abort_to_peer() {
        let state = test_state();
        let session_id = "b".repeat(64);
        state
            .registry
            .create_session(session_id.clone())
            .await
            .unwrap();

        let (alice_tx, mut alice_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        let (bob_tx, _bob_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);

        state
            .registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        state
            .registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();

        route_message(
            &state,
            &session_id,
            SessionRole::Bob,
            r#"{"type":"file_abort","transfer_id":"00112233445566778899aabbccddeeff","reason":"digest mismatch"}"#,
        )
        .await
        .unwrap();

        let Some(RelayPayload::Event(ServerEvent::RelayFileAbort {
            transfer_id,
            reason,
        })) = alice_rx.recv().await
        else {
            panic!("expected relayed file abort");
        };

        assert_eq!(transfer_id, "00112233445566778899aabbccddeeff");
        assert_eq!(reason, "digest mismatch");
    }

    #[tokio::test]
    async fn routes_file_resume_state_to_peer() {
        let state = test_state();
        let session_id = "c".repeat(64);
        state
            .registry
            .create_session(session_id.clone())
            .await
            .unwrap();

        let (alice_tx, _alice_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        let (bob_tx, mut bob_rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);

        state
            .registry
            .join(&session_id, SessionRole::Alice, alice_tx)
            .await
            .unwrap();
        state
            .registry
            .join(&session_id, SessionRole::Bob, bob_tx)
            .await
            .unwrap();

        route_message(
            &state,
            &session_id,
            SessionRole::Alice,
            r#"{"type":"file_resume_state","transfer_id":"00112233445566778899aabbccddeeff","received_bitmap":"gA=="}"#,
        )
        .await
        .unwrap();

        let Some(RelayPayload::Event(ServerEvent::RelayFileResumeState {
            transfer_id,
            received_bitmap,
        })) = bob_rx.recv().await
        else {
            panic!("expected relayed file resume state");
        };

        assert_eq!(transfer_id, "00112233445566778899aabbccddeeff");
        assert_eq!(received_bitmap, "gA==");
    }

    #[test]
    fn rejects_invalid_file_offer_fields() {
        let event = ClientEvent::FileOffer {
            transfer_id: "short".into(),
            name: "archive.bin".into(),
            mime_type: "application/octet-stream".into(),
            size: 1,
            total_chunks: 1,
            sha256: "deadbeef".into(),
        };

        assert_eq!(validate_event_size(&event), Err("invalid transfer id"));
    }

    #[test]
    fn rejects_invalid_file_resume_state_fields() {
        let event = ClientEvent::FileResumeState {
            transfer_id: "short".into(),
            received_bitmap: "gA==".into(),
        };

        assert_eq!(validate_event_size(&event), Err("invalid transfer id"));
    }
}
