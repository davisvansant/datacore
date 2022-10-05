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
