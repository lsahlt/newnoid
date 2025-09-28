/// Broadcast a JSON message to all connected clients
pub async fn broadcast_json(state: &AppState, value: serde_json::Value) {
    let msg = axum::extract::ws::Message::Text(value.to_string());
    let clients = state.clients.lock().await;
    for (_, tx) in clients.iter() {
        let _ = tx.send(msg.clone());
    }
}
// src/ws.rs
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use crate::state::AppState;
// no base64 or server-side key generation needed here; server is a dumb relay for E2EE
use crate::auth::username_for_token;

#[derive(Debug, Deserialize, Serialize)]
pub struct Hello {
    pub r#type: String, // "hello"
    pub username: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForwardMsg {
    pub r#type: String, // e.g. "pubkey", "encap", "ciphertext", "ipfs"
    pub from: String,
    pub to: Option<String>,
    pub data: Option<String>,
    // optional iv, cid, etc, kept in data or as fields if you prefer
    pub iv: Option<String>,
    pub cid: Option<String>,
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(stream: WebSocket, state: AppState) {
    // Split socket
    let (mut sender, mut receiver) = stream.split();

    // Channel for sending messages to this client
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // Task to forward messages from rx -> socket
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });
    // Do NOT register client until after successful hello handshake and token validation

    // Wait for initial hello (must be the first message)
    // Ephemeral mode: no history is sent and nothing is persisted to disk
    let hello_msg = match receiver.next().await {
        Some(Ok(Message::Text(t))) => {
            match serde_json::from_str::<Hello>(&t) {
                Ok(h) if h.r#type == "hello" => Some(h),
                _ => None,
            }
        }
        _ => None,
    };

    let hello = match hello_msg {
        Some(h) => h,
        None => {
            // close socket with reason
            let _ = tx.send(Message::Text("{\"type\":\"system\",\"msg\":\"hello required\"}".into()));
            return;
        }
    };

    // validate token → username mapping
    if let Some(expected_user) = username_for_token(&state.tokens, &hello.token).await {
        if expected_user != hello.username {
            let _ = tx.send(Message::Text("{\"type\":\"system\",\"msg\":\"invalid token\"}".into()));
            return;
        }
    } else {
        let _ = tx.send(Message::Text("{\"type\":\"system\",\"msg\":\"unknown token\"}".into()));
        return;
    }

    // register this client ONLY after successful hello; normalize to lowercase
    let uname = hello.username.to_lowercase();
    state.clients.lock().await.insert(uname.clone(), tx.clone());
    // Broadcast presence after connect
    broadcast_presence(&state).await;
    // Note: Browser is the source of truth for Kyber keys. Server does not generate or broadcast keys.

    // Notify system join
    let sys = serde_json::json!({"type":"system","msg": format!("{} connected", uname)});
    broadcast_json(&state, sys).await;

    // main read loop: forward messages
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(txt) => {
                println!("[ws] Received message: {}", txt);
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(val) => val,
                    Err(e) => {
                        println!("[ws] Invalid message format: {} | Error: {}", txt, e);
                        let _ = tx.send(Message::Text("{\"type\":\"system\",\"msg\":\"invalid message format\"}".into()));
                        continue;
                    }
                };
                match v.get("type").and_then(|t| t.as_str()) {
                    Some("ciphertext") => {
                        println!("[ws] [E2EE] Received ciphertext message");
                        let ciphertext = v.get("ciphertext").and_then(|c| c.as_str()).unwrap_or("").to_string();
                        let nonce = v.get("nonce").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        let kyber_ct = v.get("kyber_ct").and_then(|k| k.as_str()).unwrap_or("").to_string();
                        println!("[ws] [E2EE] Raw values:\n  ciphertext: {}\n  nonce: {}\n  kyber_ct: {}", ciphertext, nonce, kyber_ct);
                        let to = v.get("to").and_then(|t| t.as_str()).map(|s| s.to_string());
                        let from = v.get("from").and_then(|f| f.as_str()).unwrap_or("").to_string();
                        println!("[ws] [E2EE] From: {} To: {:?}", from, to);
                        println!("[ws] [E2EE] Ciphertext: {}\nNonce: {}\nKyber_ct: {}", ciphertext, nonce, kyber_ct);
                        // Ephemeral mode: do not persist ciphertext to DB
                        // Route to specific user and echo to sender so they see their own message
                        if let Some(to) = to {
                            let clients = state.clients.lock().await;
                            let mut echoed = false;
                            if let Some(dest_tx) = clients.get(&to) {
                                let send_result = dest_tx.send(Message::Text(txt.clone()));
                                println!("[ws] [E2EE] Sent ciphertext to '{}': {:?}", to, send_result);
                            }
                            let from_lc = from.to_lowercase();
                            if let Some(sender_tx) = clients.get(&from_lc) {
                                let send_result = sender_tx.send(Message::Text(txt.clone()));
                                echoed = true;
                                println!("[ws] [E2EE] Echoed ciphertext back to sender '{}': {:?}", from_lc, send_result);
                            }
                            if !echoed {
                                println!("[ws] [E2EE] Could not echo to sender '{}' (not found)", from_lc);
                            }
                        }
                    }
                    Some("plaintext") => {
                        println!("[ws] [PLAINTEXT] Received plaintext message");
                        if let Ok(f) = serde_json::from_value::<ForwardMsg>(v.clone()) {
                            let from = f.from.clone();
                            let to = f.to.clone();
                            let data = f.data.clone().unwrap_or_default();
                            println!("[ws] [PLAINTEXT] Fields: from={}, to={:?}, data={}", from, to, data);
                            // Ephemeral mode: do not persist plaintext
                            // If `to` present, route to specific user
                            if let Some(to) = f.to.clone() {
                                let clients = state.clients.lock().await;
                                if let Some(dest_tx) = clients.get(&to) {
                                    let send_result = dest_tx.send(Message::Text(txt.clone()));
                                    println!("[ws] Sent plaintext to '{}': {:?}", to, send_result);
                                }
                                // Echo plaintext back to sender so they see their own message
                                let from_lc = from.to_lowercase();
                                if let Some(sender_tx) = clients.get(&from_lc) {
                                    let _ = sender_tx.send(Message::Text(txt.clone()));
                                }
                            }
                        }
                    }
                    _ => {
                        println!("[ws] Unknown message type: {:?}", v.get("type"));
                    }
                }
            }
            Message::Binary(data) => {
                println!("[ws] Received binary message: {:?}", data);
            }
            Message::Ping(data) => {
                println!("[ws] Received ping: {:?}", data);
            }
            Message::Pong(data) => {
                println!("[ws] Received pong: {:?}", data);
            }
            Message::Close(frame) => {
                println!("[ws] Received close frame: {:?}", frame);
            }
        }
    }
    // Cleanup on disconnect: remove client and broadcast presence
    // remove normalized key
    state.clients.lock().await.remove(&uname);
    broadcast_presence(&state).await;
}

// Broadcast the list of currently online users to all clients
async fn broadcast_presence(state: &AppState) {
    let clients = state.clients.lock().await;
    let online: Vec<String> = clients.keys().cloned().collect();
    drop(clients);
    let msg = serde_json::json!({
        "type": "presence",
        "online": online,
    });
    broadcast_json(state, msg).await;
}
