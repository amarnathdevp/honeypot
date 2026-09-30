pub struct RequestInfo {
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub query: Option<String>,
    pub client_ip: String,
    pub request_body: String,
}