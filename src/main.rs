use axum::routing::get_service;
use tower_http::services::{ServeDir, ServeFile};
mod state;
mod auth;
mod ws;
mod routes;
mod ipfs;
pub mod crypto;

use axum::{Router, routing::{get, post}};
use axum::http::StatusCode;
use tower_http::trace::TraceLayer;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::{CACHE_CONTROL, HeaderValue};
use std::net::SocketAddr;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = AppState::new();

    let app = Router::new()
        // Avoid console 404 noise for favicon
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        // Explicit file route to ensure kyber.js is served correctly
        .route_service(
            "/static/kyber.js",
            get_service(ServeFile::new(r"C:/Users/Hurtf/OneDrive/Desktop/noid-messenger/static/kyber.js"))
                .handle_error(|error: std::io::Error| async move {
                    println!("[STATIC] Error serving kyber.js: {}", error);
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Static file error: {}", error))
                })
        )
        .route("/", get(routes::index))
        .route("/login", post(routes::login_handler))
        .route("/ipfs/add", post(routes::ipfs_add))
        .route("/chat", get(routes::chat))
        .route("/ws", get(ws::ws_handler))
        .route("/pubkey", post(routes::post_pubkey))
        .route("/pubkeys", get(routes::get_pubkeys))
        .route_service(
            "/static/*file",
            get_service(ServeDir::new(r"C:/Users/Hurtf/OneDrive/Desktop/noid-messenger/static"))
                .handle_error(|error: std::io::Error| async move {
                    // Print debug info for static file errors
                    println!("[STATIC] Error serving file: {}", error);
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Static file error: {}", error))
                })
        )
    .with_state(state.clone())
    // Compression first, then tracing
    .layer(CompressionLayer::new())
    // Cache static responses where possible
    .layer(SetResponseHeaderLayer::if_not_present(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=600, s-maxage=600"),
    ))
    // Log all requests/responses to help diagnose 404s (can be reduced later)
    .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
