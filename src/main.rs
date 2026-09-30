
mod app;
mod handlers;

mod state;

mod models;

mod security;
mod router;
mod db;



use std::env;
use std::net::SocketAddr;
use sqlx::PgPool;
use crate::state::AppState;
// mod

#[tokio::main]


async fn main (){

    dotenvy::dotenv().ok();

    println!("JWT_SECRET loaded: {}",
    env::var("JWT_SECRET")
        .is_ok()
    );

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");



    let db:PgPool = db::connection::create_pool(&database_url)
    .await
        .expect("Failed to connect to database");

    println!("Database connected");

    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("Failed to migrate");

    println!("Database migrations completed");


    let state = AppState{
        db_pool:db
    };

    let app = app::create_app(state);



    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();

    println!("Honeypot server running on http://127.0.0.1:8080");
    axum::serve(listener,app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}