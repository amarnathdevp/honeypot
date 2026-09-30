

use axum::{routing::{get,post}, Router};
use crate::handlers::auth::{login, register, protected};
use crate::handlers::health::health;
use crate::handlers::honeypot::honeypot;
use crate::handlers::home::home;
use crate::handlers::alert::{
    get_alert,
    get_alert_by_id,
    get_alert_stats,
    get_dashboard,
};


use crate::state::AppState;

pub fn create_router() ->Router<AppState>{
    Router::new()
        .route("/", get(home))
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/protected", get(protected))
        .route("/alert", get(get_alert))
        .route("/alert/stats", get(get_alert_stats))
        .route("/alert/{id}", get(get_alert_by_id))
        .route("/dashboard", get(get_dashboard))
        .route("/{*path}", get(honeypot).post(honeypot))
        .route("/register", post(register))
}