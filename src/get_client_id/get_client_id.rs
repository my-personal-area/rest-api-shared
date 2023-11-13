use service_sdk::my_http_server::{HttpContext, HttpFailResult, WebContentType};

pub trait GetClientId {
    fn get_client_id(&self) -> Result<&str, HttpFailResult>;
}

impl GetClientId for HttpContext {
    fn get_client_id(&self) -> Result<&str, HttpFailResult> {
        if let Some(credentials) = self.credentials.as_ref() {
            Ok(credentials.get_id())
        } else {
            Err(HttpFailResult::new(
                WebContentType::Text,
                401,
                "Unauthenticated".as_bytes().to_vec(),
                false,
                false,
            ))
        }
    }
}
