use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct AuthenticationError {
    pub error: AuthenticationErrorType,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum AuthenticationErrorType {
    UnknownError,
    NotSupportedError,
    InvalidStateError,
    NotAllowedError,
    ConstraintError,
    OperationError,
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error {
            AuthenticationErrorType::UnknownError => write!(f, "UnknownError"),
            AuthenticationErrorType::NotSupportedError => write!(f, "NotSupportedError"),
            AuthenticationErrorType::InvalidStateError => write!(f, "InvalidStateError"),
            AuthenticationErrorType::NotAllowedError => write!(f, "NotAllowedError"),
            AuthenticationErrorType::ConstraintError => write!(f, "ContraintError"),
            AuthenticationErrorType::OperationError => write!(f, "OperationError"),
        }
    }
}

impl std::error::Error for AuthenticationError {}
