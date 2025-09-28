// src/auth.rs
use once_cell::sync::Lazy;
use std::collections::HashMap;
use uuid::Uuid;
use crate::state::TokenMap;

/// Hardcoded user database (username -> bcrypt hash)
/// Passwords: alice123, bob123 (for demo). In production, never commit plaintext!
static USERS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // These are bcrypt hashes of "alice123" and "bob123" created once.
    // If you want to recreate, run hash("alice123", DEFAULT_COST) locally
    m.insert("alice", "$2b$12$GXs2fE4sU7o4n0mQJm7K0u8sYf2lq7H2YZy7wT6oH0vQY9FJ0PR1y"); // EXAMPLE placeholder
    m.insert("bob", "$2b$12$XKq1f8R8q0k6YvI6Oa9aYe1G2nYk7s2tL5Q9j8ZpV5fL3cQ1J5kIa");   // EXAMPLE placeholder
    m
});

/// Verify username/password. Returns true if valid.
pub async fn verify_login(username: &str, password: &str) -> bool {
    // NOTE: For demo, we accept if username == "alice" && password == "alice123", etc.
    // The hashed constants above are placeholders — it's often simpler in a hackathon
    // to directly check plaintext for speed. Replace with real hashes in production.

    match username {
        "alice" => password == "alice123",
        "bob" => password == "bob123",
        _ => false
    }
}

/// Create a session token and store it in tokens map
pub async fn create_token_for_user(tokens: &TokenMap, username: &str) -> String {
    let token = Uuid::new_v4().to_string();
    tokens.lock().await.insert(token.clone(), username.to_string());
    token
}

/// Validate token and return username (if any)
pub async fn username_for_token(tokens: &TokenMap, token: &str) -> Option<String> {
    tokens.lock().await.get(token).cloned()
}
