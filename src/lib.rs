use std::sync::RwLock;
pub use middleware::Oauth2;
pub use refresh::RefreshConfig;

mod middleware;
mod refresh;
mod step2_exchange;
mod step1_init;

pub use step1_init::{Initialize};
use step1_init::{InitializeParams};
use httpclient::{Uri, client, Result};
use crate::middleware::TokenType;
use crate::step2_exchange::{ExchangeData, ExchangeResponse, RedirectedParams};
use httpclient::InMemoryResponseExt;

/// There are two key structs in this module: `Oauth2Flow` and `Oauth2`.
/// Oauth2Flow brings the user through the Oauth2 flow, and Oauth2
/// is a middleware used to authorize requests.

/// The main entry point for taking the user through OAuth2 flow.
pub struct Oauth2Flow {
    pub client_id: String,
    pub client_secret: String,

    /// The endpoint to initialize the flow. (Step 1)
    pub init_endpoint: String,
    /// The endpoint to exchange the code for an access token. (Step 2)
    pub exchange_endpoint: String,
    /// The endpoint to refresh the access token.
    pub refresh_endpoint: String,

    pub redirect_uri: String,
}

impl Oauth2Flow {
    /// Step 1: Send the user to the authorization URL.
    pub fn create_authorization_url(&self, init: Initialize) -> Uri {
        let params = InitializeParams {
            client_id: &self.client_id,
            redirect_uri: &self.redirect_uri,
            response_type: "code",
            scope: init.scope,
            access_type: init.access_type,
            state: init.state,
            prompt: init.prompt,
        };
        let params = serde_qs::to_string(&params).unwrap();
        let endpoint = self.init_endpoint.as_str();
        let uri = format!("{endpoint}?{params}");
        uri.parse().unwrap()
    }

    /// Step 2a: Extract the code from the redirect URL.
    pub async fn extract_code(&self, url: String) -> Result<RedirectedParams> {
        let uri = url.parse::<Uri>().unwrap();
        let query = uri.query().unwrap();
        let params = serde_qs::from_str::<RedirectedParams>(query).unwrap();
        Ok(params)
    }

    pub fn create_exchange_data(&self, code: String) -> ExchangeData {
        ExchangeData {
            code,
            client_id: &self.client_id,
            redirect_uri: &self.redirect_uri,
            client_secret: &self.client_secret,
            grant_type: "authorization_code",
        }
    }

    /// Step 2b: Using RedirectedParams.code, POST to the exchange_endpoint to get the access token.
    pub async fn exchange(&self, code: String) -> Result<ExchangeResponse> {
        let data = self.create_exchange_data(code);
        client().post(&self.exchange_endpoint)
            .form(data)
            .await?
            .json()
            .map_err(|e| e.into())
    }

    /// Step 3: Use the exchange response to create a middleware. You can also use `middleware_from_pieces`.
    pub fn middleware_from_exchange(&self, exchange: ExchangeResponse) -> Oauth2 {
        Oauth2 {
            refresh_endpoint: self.refresh_endpoint.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            token_type: exchange.token_type,
            access_token: RwLock::new(exchange.access_token),
            refresh_token: exchange.refresh_token,
            callback: None,
        }
    }

    pub fn middleware_from_pieces(&self, access: String, refresh: String, token: TokenType) -> Oauth2 {
        Oauth2 {
            refresh_endpoint: self.refresh_endpoint.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            token_type: token,
            access_token: RwLock::new(access),
            refresh_token: refresh,
            callback: None,
        }
    }
}