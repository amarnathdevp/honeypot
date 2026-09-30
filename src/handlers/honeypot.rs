use std::net::SocketAddr;


use axum::{
    body::Bytes,
    extract::{ConnectInfo,Path,  RawQuery, State},
    http::{HeaderMap, Method,StatusCode},

};
use crate::models::alert::Alert;
use crate::models::request::RequestInfo;
use crate::security::detector::detect;
use crate::security::logger::logger_alert;
use crate::security::scorer::score;
use crate::state::AppState;





pub async fn honeypot(
    State(state): State<AppState>,
    ConnectInfo(addr):ConnectInfo<SocketAddr>,
    method: Method,
    Path(path): Path<String>,
   RawQuery(query):RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> ( StatusCode,String) {
    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let client_ip = addr.ip().to_string();

    let request_body = String::from_utf8_lossy(&body).to_string();


    println!("Query : {:?}", query);
    println!("Client IP: {}",client_ip);
    println!("Request Body : {}", request_body);



    let request = RequestInfo {
        method: method.to_string(),
        path,
        user_agent,
        query,
       client_ip,
        request_body

    };

    let attack = detect(&request);

    if let Some(attack_type) = attack {
        let risk = score(&attack_type);

        let alert = Alert {
            attack_type: format!("{:?}", attack_type),
            risk: risk.to_string(),
        };

       if let Err(error)= logger_alert(
            &state.db_pool,
            &request,
            &alert,
        )
            .await

       {
           eprintln!("failed to log alert: {}", error);
           return (StatusCode::INTERNAL_SERVER_ERROR,"Internal Server Error ".to_string());

           
       }
        (
       StatusCode::FORBIDDEN,
        format!(
            "SUSPICIOUS REQUEST\n\
             Method: {}\n\
             Path: /{}\n\
             User-Agent: {}\n\
             Attack: {}\n\
             Risk: {}\n\
             Client_IP: {}",
            request.method,
            request.path,
            request.user_agent,
            alert.attack_type,
            alert.risk,
            request. client_ip,
        ))
    } else {
        (StatusCode::NOT_FOUND,
        format!(
            "404 NOT Found\n\
             Method: {}\n\
             Path: /{}\n\
             Client_IP : {}",
            request.method,
            request.path,
            request.client_ip,
        ))
    }
}