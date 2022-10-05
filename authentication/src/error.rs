#[derive(Debug)]
pub struct AuthenticationError {
    pub error: AuthenticationErrorType,
}

#[derive(Debug)]
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
        write!(f, "Authentication Error!")
    }
}

impl std::error::Error for AuthenticationError {}
