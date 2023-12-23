use serde::{Deserialize, Serialize};
use crate::middleware::TokenType;

/// The params returned
#[derive(Debug, Deserialize)]
pub struct RedirectedParams {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExchangeData<'a> {
    pub code: String,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub grant_type: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
    pub token_type: TokenType,
}