mod api_result_status;
mod get_client_id;

pub mod middlewares;
pub use api_result_status::*;
pub use get_client_id::*;
#[cfg(feature = "auth-middleware")]
mod configure_rest_api_server;
#[cfg(feature = "auth-middleware")]
pub use configure_rest_api_server::*;

#[cfg(not(feature = "auth-middleware"))]
mod configure_rest_api_server_with_no_auth_middleware;
#[cfg(not(feature = "auth-middleware"))]
pub use configure_rest_api_server_with_no_auth_middleware::*;
