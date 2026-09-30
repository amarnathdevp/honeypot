
use axum::Router;

use crate::router::create_router;
use crate::state::AppState;

pub fn create_app(state: AppState) -> Router {
    create_router()
        .with_state(state)
}