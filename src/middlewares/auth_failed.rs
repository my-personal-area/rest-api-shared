use crate::ApiResultStatus;
use my_http_server::macros::MyHttpObjectStructure;
use my_http_server::HttpFailResult;
use serde::Serialize;
use service_sdk::my_http_server;

#[derive(Serialize, Debug, MyHttpObjectStructure)]
pub struct AuthenticationFailedApiResponse {
    #[serde(rename = "result")]
    pub result: ApiResultStatus,
    #[serde(rename = "description")]
    pub description: String,
}

#[derive(Serialize, Debug, MyHttpObjectStructure)]
pub struct AuthorizationFailedApiResponse {
    pub result: ApiResultStatus,
    pub description: String,
}

impl AuthorizationFailedApiResponse {
    pub fn new(result: ApiResultStatus, description: String) -> HttpFailResult {
        let result = AuthorizationFailedApiResponse {
            result,
            description,
        };

        let content = serde_json::to_vec(&result).unwrap();
        HttpFailResult::new(
            my_http_server::WebContentType::Json,
            403,
            content,
            false,
            false,
        )
    }

    pub fn default_desc() -> String {
        "Authorization required".to_string()
    }
}

impl AuthenticationFailedApiResponse {
    pub fn new(result: ApiResultStatus, description: String) -> HttpFailResult {
        let result = AuthenticationFailedApiResponse {
            result,
            description,
        };

        let content = serde_json::to_vec(&result).unwrap();

        HttpFailResult::new(
            my_http_server::WebContentType::Json,
            401,
            content,
            false,
            false,
        )
    }

    pub fn default_desc() -> String {
        "Authentication required".to_string()
    }
}

use my_http_server::controllers::documentation::{
    data_types::HttpDataType, out_results::HttpResult,
};

pub struct AuthFailResponseFactory;

impl my_http_server::controllers::AuthErrorFactory for AuthFailResponseFactory {
    fn get_not_authenticated(&self) -> my_http_server::HttpFailResult {
        return AuthenticationFailedApiResponse::new(
            ApiResultStatus::AccessTokenExpired,
            AuthenticationFailedApiResponse::default_desc(),
        );
    }

    fn get_not_authorized(&self, claim_name: String) -> my_http_server::HttpFailResult {
        return AuthorizationFailedApiResponse::new(
            ApiResultStatus::AccessClaimRequired,
            claim_name,
        );
    }
    fn get_global_http_fail_result_types(&self) -> Option<Vec<HttpResult>> {
        let authentication_http_structure =
            AuthenticationFailedApiResponse::get_http_data_structure();
        let authorization_http_structure =
            AuthorizationFailedApiResponse::get_http_data_structure();

        Some(vec![
            HttpResult {
                http_code: 401,
                nullable: false,
                description: AuthenticationFailedApiResponse::default_desc(),
                data_type: HttpDataType::Object(authentication_http_structure),
            },
            HttpResult {
                http_code: 403,
                nullable: false,
                description: AuthorizationFailedApiResponse::default_desc(),
                data_type: HttpDataType::Object(authorization_http_structure),
            },
        ])
    }
}
