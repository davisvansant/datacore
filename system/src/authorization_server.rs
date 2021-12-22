use axum::routing::get;
use axum::Router;

pub struct AuthorizationServer {}

impl AuthorizationServer {
    pub async fn init() -> AuthorizationServer {
        AuthorizationServer {}
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client_registration = Router::new().route(
            "/client_registration",
            get(AuthorizationServer::client_registration),
        );

        axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
            .serve(client_registration.into_make_service())
            .await?;

        Ok(())
    }

    async fn client_registration() -> &'static str {
        "hello from client registration!"
    }
}
