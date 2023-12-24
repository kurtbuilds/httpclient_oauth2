use std::sync::RwLock;
use httpclient::ResponseExt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use httpclient::{header, HeaderName, InMemoryRequest, Method, Middleware, Next, RequestBuilder, Result};
use crate::refresh::RefreshResponse;


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TokenType {
    Bearer,
    Other(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshData {
    pub access_token: String,
}

#[derive(Debug)]
pub struct OAuth2 {
    // Configuration
    pub refresh_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_type: TokenType,

    // State
    pub access_token: RwLock<String>,
    pub refresh_token: String,

    pub callback: Option<fn(RefreshData) -> ()>,
}

impl OAuth2 {
    fn authorize(&self, mut request: InMemoryRequest) -> InMemoryRequest {
        let access_token = self.access_token.read().unwrap();
        let access_token = access_token.as_str();
        match &self.token_type {
            TokenType::Bearer => {
                request.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {}", access_token).parse().unwrap());
            }
            TokenType::Other(s) => {
                request.headers_mut().insert(s.parse::<HeaderName>().unwrap(), access_token.parse().unwrap());
            }
        }
        request
    }
}

#[async_trait]
impl Middleware for OAuth2 {
    async fn handle(&self, request: InMemoryRequest, next: Next<'_>) -> Result {
        let req = self.authorize(request);
        let res = next.run(req.clone().into()).await?;
        let status = res.status().as_u16();
        if ![400, 401].contains(&status) {
            return Ok(res);
        }
        let refresh_req = RequestBuilder::new(next.client, Method::POST, self.refresh_endpoint.parse().unwrap())
            .json(RefreshRequest {
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                grant_type: "refresh_token",
                refresh_token: &self.refresh_token,
            })
            .build();
        let res = next.run(refresh_req).await?;
        let data: RefreshResponse = res.json().await?;
        {
            let mut access_token = self.access_token.write().unwrap();
            *access_token = data.access_token.clone();
        }
        if let Some(callback) = self.callback {
            callback(RefreshData {
                access_token: data.access_token,
            });
        }
        // reauthorize the request with the newly set access token. it will overwrite the previously set headers
        let req = self.authorize(req);
        next.run(req.clone().into()).await
    }
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub grant_type: &'static str,
    pub refresh_token: &'a str,
}

