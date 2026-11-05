//! Error types.

use std::fmt;
use std::time::Duration;

use serde_json::Value;

use crate::discovery::ParamProblem;
use crate::util::{lenient_i64, lenient_string};

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error reported by the CloudStack management server itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status of the response that carried the error (200 for failed async jobs).
    pub http_status: u16,
    /// CloudStack `errorcode` (mostly mirrors an HTTP status, e.g. 431 for bad parameters).
    pub error_code: Option<i64>,
    /// CloudStack internal `cserrorcode`, identifying the Java exception class.
    pub cs_error_code: Option<i64>,
    /// Human-readable `errortext`.
    pub error_text: String,
}

impl ApiError {
    /// Extracts an error from an (unwrapped) response body, if it describes one.
    pub(crate) fn from_body(http_status: u16, body: &Value) -> Option<Self> {
        let obj = body.as_object()?;
        if !obj.contains_key("errorcode") && !obj.contains_key("errortext") {
            return None;
        }
        Some(Self {
            http_status,
            error_code: obj.get("errorcode").and_then(lenient_i64),
            cs_error_code: obj.get("cserrorcode").and_then(lenient_i64),
            error_text: obj
                .get("errortext")
                .and_then(lenient_string)
                .unwrap_or_else(|| "unknown error".to_owned()),
        })
    }

    /// True when the server rejected the credentials, signature or session.
    pub fn is_auth_failure(&self) -> bool {
        self.http_status == 401 || self.error_code == Some(401)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error_text)?;
        match (self.error_code, self.cs_error_code) {
            (Some(code), Some(cs)) => write!(f, " (errorcode {code}, cserrorcode {cs})"),
            (Some(code), None) => write!(f, " (errorcode {code})"),
            _ => write!(f, " (HTTP {})", self.http_status),
        }
    }
}

/// Everything that can go wrong when talking to CloudStack.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The client was configured incorrectly.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Transport-level failure (DNS, TLS, connection, timeout, ...).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The management server returned an error response.
    #[error("CloudStack API error: {0}")]
    Api(ApiError),

    /// The account has 2FA enabled and no code provider was configured.
    #[error("two-factor authentication is required but no code provider is configured")]
    TwoFactorRequired,

    /// The requested API does not exist (or is not available to this account's role).
    #[error("unknown API `{name}`{}", did_you_mean(.suggestions))]
    UnknownApi { name: String, suggestions: Vec<String> },

    /// Client-side validation against the discovered API metadata failed.
    #[error("invalid parameters for `{api}`: {}", join(.problems))]
    InvalidParams { api: String, problems: Vec<ParamProblem> },

    /// An async job finished with status "failed".
    #[error("async job {job_id} failed: {error}")]
    JobFailed {
        job_id: String,
        error: ApiError,
        result: Value,
    },

    /// An async job did not finish within the configured timeout.
    #[error("async job {job_id} did not finish within {timeout:?}")]
    JobTimeout { job_id: String, timeout: Duration },

    /// The server answered with something that is not a CloudStack API response.
    #[error("unexpected response (HTTP {status}): {message}")]
    UnexpectedResponse { status: u16, message: String },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The server-side error, if this is one (including failed async jobs).
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Error::Api(e) | Error::JobFailed { error: e, .. } => Some(e),
            _ => None,
        }
    }

    /// True when the request was rejected because of credentials, signature or session.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Error::Api(e) if e.is_auth_failure())
    }
}

fn did_you_mean(suggestions: &[String]) -> String {
    if suggestions.is_empty() {
        String::new()
    } else {
        format!("; did you mean {}?", suggestions.join(", "))
    }
}

fn join(problems: &[ParamProblem]) -> String {
    problems.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}
