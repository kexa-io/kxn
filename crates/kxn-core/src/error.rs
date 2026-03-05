use thiserror::Error;

#[derive(Debug, Error)]
pub enum KxnError {
    #[error("Property not found: {0}")]
    PropertyNotFound(String),

    #[error("Invalid condition: {0}")]
    InvalidCondition(String),

    #[error("Type mismatch: {0}")]
    TypeMismatch(String),

    #[error("Invalid regex: {0}")]
    InvalidRegex(String),

    #[error("Invalid date: {0}")]
    InvalidDate(String),

    #[error("Rule parse error: {0}")]
    RuleParse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
