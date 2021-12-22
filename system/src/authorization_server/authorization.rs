use super::AuthorizationServer;

impl AuthorizationServer {
    pub(crate) async fn authorization() -> &'static str {
        "grant"
    }
}
