use axum::handler::Handler;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;

pub struct AuthorizationServer {}

impl AuthorizationServer {
    pub async fn init() -> AuthorizationServer {
        AuthorizationServer {}
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let token_routes = Router::new()
            .route("/token", get(AuthorizationServer::token))
            .route("/token", post(AuthorizationServer::token));

        Router::new()
            .route("/authorization", get(AuthorizationServer::authorization))
            .route(
                "/client_registration",
                get(AuthorizationServer::client_registration),
            )
            .merge(token_routes)
            .fallback(AuthorizationServer::fallback.into_service())
    }

    async fn authorization() -> &'static str {
        "grant"
    }

    async fn client_registration() -> &'static str {
        "hello from client registration!"
    }

    async fn fallback(uri: Uri) -> impl IntoResponse {
        (StatusCode::NOT_FOUND, format!("No route for {}", uri))
    }

    async fn token() -> &'static str {
        "token"
    }
}
