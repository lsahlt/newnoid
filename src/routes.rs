// Add Kyber public key endpoints
use axum::Json;
use std::sync::Arc;
use std::collections::HashMap;

// In-memory store for demo (replace with DB for production)
static KYBER_PUBKEYS: once_cell::sync::Lazy<Arc<std::sync::Mutex<HashMap<String, String>>>> = once_cell::sync::Lazy::new(|| Arc::new(std::sync::Mutex::new(HashMap::new())));

pub async fn post_pubkey(Json(payload): Json<HashMap<String, String>>) -> axum::response::Result<String> {
    let username = payload.get("username").cloned().unwrap_or_default();
    let pubkey = payload.get("pubkey").cloned().unwrap_or_default();
    if !username.is_empty() && !pubkey.is_empty() {
        KYBER_PUBKEYS.lock().unwrap().insert(username, pubkey);
        Ok("ok".to_string())
    } else {
        Ok("missing username or pubkey".to_string())
    }
}

pub async fn get_pubkeys() -> axum::response::Result<Json<HashMap<String, String>>> {
    let keys = KYBER_PUBKEYS.lock().unwrap().clone();
    Ok(Json(keys))
}
// src/routes.rs
use axum::{
    routing::{get, post},
    Router, extract::State,
    response::{IntoResponse},
};
use base64::Engine;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use crate::auth;
use crate::ipfs;

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResp {
    pub ok: bool,
    pub token: Option<String>,
    pub msg: Option<String>,
}

pub fn routes(state: crate::state::AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login_handler))
        .route("/ipfs/add", post(ipfs_add))
    // Kyber public key exchange endpoints (browser-provided)
    .route("/pubkey", post(post_pubkey))
    .route("/pubkeys", get(get_pubkeys))
        .route("/chat", get(chat))
        .with_state(state)
}

/// serve static index.html
pub async fn index() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/index.html"))
}

pub async fn login_handler(State(state): State<AppState>, Json(payload): Json<LoginReq>) -> impl IntoResponse {
    println!("[LOGIN] Attempt user='{}'", payload.username);
    if auth::verify_login(&payload.username, &payload.password).await {
        let token = auth::create_token_for_user(&state.tokens, &payload.username).await;
        println!("[LOGIN] Success user='{}' token='{}'", payload.username, token);
        let resp = LoginResp { ok: true, token: Some(token), msg: None };
        (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
    } else {
        println!("[LOGIN] Failed user='{}' (invalid credentials)", payload.username);
        let resp = LoginResp { ok: false, token: None, msg: Some("invalid credentials".into())};
        (axum::http::StatusCode::UNAUTHORIZED, axum::Json(resp)).into_response()
    }
}

pub async fn chat() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/chat.html"))
}

/// Simple IPFS add endpoint that accepts {"data": "<base64>"} and returns { cid }
#[derive(Deserialize)]
pub struct IpfsAddReq {
    data_b64: String,
}

#[derive(Serialize)]
struct IpfsAddResp {
    ok: bool,
    cid: Option<String>,
    msg: Option<String>,
}

pub async fn ipfs_add(State(_state): State<AppState>, Json(payload): Json<IpfsAddReq>) -> impl IntoResponse {
    // Decode base64
    let bytes = match base64::engine::general_purpose::STANDARD.decode(&payload.data_b64) {
        Ok(b) => b,
        Err(e) => return (axum::http::StatusCode::BAD_REQUEST, Json(IpfsAddResp { ok:false, cid:None, msg: Some(format!("bad base64: {}", e))})),
    };

    match ipfs::add_bytes_to_ipfs(bytes).await {
        Ok(cid) => (axum::http::StatusCode::OK, Json(IpfsAddResp { ok:true, cid:Some(cid), msg:None })),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(IpfsAddResp { ok:false, cid:None, msg:Some(format!("{}", e)) })),
    }
}
