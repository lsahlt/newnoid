// src/state.rs
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, mpsc};
use axum::extract::ws::Message;
// For Kyber key management
pub struct UserKeys {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub type Tx = mpsc::UnboundedSender<Message>;
pub type ClientsMap = Arc<Mutex<HashMap<String, Tx>>>;

/// Maps short session tokens -> username
pub type TokenMap = Arc<Mutex<HashMap<String, String>>>;

#[derive(Clone)]
pub struct AppState {
    /// Connected clients (username -> sender)
    pub clients: ClientsMap,
    /// Login tokens (token -> username)
    pub tokens: TokenMap,
    /// Kyber keypairs (username -> keys)
    pub user_keys: Arc<Mutex<HashMap<String, UserKeys>>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            clients: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            user_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
