pub struct AuthenticationError {
    pub error: AuthenticationErrorType,
}

pub enum AuthenticationErrorType {
    UnknownError,
    NotSupportedError,
    InvalidStateError,
    NotAllowedError,
    ConstraintError,
}
