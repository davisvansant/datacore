use std::net::SocketAddr;

use axum::handler::Handler;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use axum::Server;

mod authentication;
mod token;
mod userinfo;

pub struct AuthorizationServer {
    socket_address: SocketAddr,
}

impl AuthorizationServer {
    pub async fn init(socket_address: SocketAddr) -> AuthorizationServer {
        AuthorizationServer { socket_address }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let authentication_routes = Router::new()
            .route("/authorize", get(AuthorizationServer::authentication))
            .route("/authorize", post(AuthorizationServer::authentication));

        let token_routes = Router::new()
            .route("/token", get(AuthorizationServer::token))
            .route("/token", post(AuthorizationServer::token));

        let userinfo_routes = Router::new()
            .route("/userinfo", get(AuthorizationServer::userinfo))
            .route("userinfo", post(AuthorizationServer::userinfo));

        Router::new()
            .route(
                "/client_registration",
                get(AuthorizationServer::client_registration),
            )
            .merge(authentication_routes)
            .merge(token_routes)
            .merge(userinfo_routes)
            .fallback(AuthorizationServer::fallback.into_service())
    }

    async fn client_registration() -> &'static str {
        "hello from client registration!"
    }

    async fn fallback(uri: Uri) -> impl IntoResponse {
        (StatusCode::NOT_FOUND, format!("No route for {}", uri))
    }
}
