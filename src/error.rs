use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
	#[error("Usage: scanner <url>")]
	CLiUsage,
	#[error("Reqwest: {0}")]
	Reqwest(String),
	#[error("tokio join error: {0}")]
	TokioJoinError(String),
	#[error("Invalid Http response: {0}")]
	InvalidHttpResponse(String),
}

impl From<reqwest::Error> for Error {
	fn from(error: reqwest::Error) -> Self {
		Error::Reqwest(error.to_string())
	}
}

impl From<tokio::task::JoinError> for Error {
	fn from(err: tokio::task::JoinError) -> Self {
		Error::TokioJoinError(err.to_string())
	}
}