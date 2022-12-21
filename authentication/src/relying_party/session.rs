use serde::{Deserialize, Serialize};

use crate::security::session_token::{generate_session_token, SessionToken};
use crate::security::uuid::{generate_session_id, SessionId};

pub use active::Active;
pub use available::Available;

mod active;
mod available;

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub token: SessionToken,
}

impl SessionInfo {
    pub async fn generate() -> SessionInfo {
        SessionInfo {
            id: generate_session_id().await,
            token: generate_session_token().await,
        }
    }
}
