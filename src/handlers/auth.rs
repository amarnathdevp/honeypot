use jsonwebtoken::{decode,encode, DecodingKey,EncodingKey, Validation,Header};
use std::env;

use axum::extract::State;
use axum::{http::{HeaderMap,StatusCode}, Json};

use crate::models::claim::Claim;
use crate::models::log::LoginRequest;
use crate::models::register::RegisterRequest;
use crate::state::AppState;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<String, StatusCode> {
    println!("username: {}", payload.username);

    let hash_password = bcrypt::hash(payload.password, 12)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("hash: {}", hash_password);

    sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        "#,
        payload.username,
        hash_password
    )
        .execute(&state.db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok("Register request received".to_string())
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<String, StatusCode> {
    let secret = env::var("JWT_SECRET")
        .expect("JWT_SECRET Must be set");

    println!("Secret loaded {}", secret);

    let _user = sqlx::query!(
        r#"
        SELECT password_hash
        FROM users
        WHERE username = $1
        "#,
        payload.username,
    )
        .fetch_one(&state.db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
 let exp = (chrono::Utc::now() .timestamp() + 3000)as usize;
    let claim = Claim {
        sub: payload.username.clone(),
        exp,
    };
    let password_valid = bcrypt::verify(
        &payload.password,
        &_user.password_hash,
    )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !password_valid{
        return Err(StatusCode::UNAUTHORIZED);
    }

    let key = EncodingKey::from_secret(secret.as_bytes());


    let token = encode(
        &Header::default(),
        &claim,
        &key,
    )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token)
}
pub fn validate_token(
    token: &str,
    secret: &str,
) -> Result<Claim, StatusCode> {

    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::default();
    let token_data = decode::<Claim>(
        token,
       &key,
        &validation,
    )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(token_data.claims)
}
pub async fn protected(headers: HeaderMap) ->Result<(),StatusCode>{

    let auth = headers.get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth= auth
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;


    let secret = env::var("JWT_SECRET")
        .map_err(|_|StatusCode::UNAUTHORIZED)?;

    let claim = validate_token(token, &secret)?;
    println!("Authenticated user: {}", claim.sub);

    Ok(())


}
#[test]
fn test_expired_token() {
    let secret = "test-secret";

    let claim = Claim {
        sub: "testuser".to_string(),
        exp: 1,
    };

    let key = EncodingKey::from_secret(secret.as_bytes());

    let token = encode(
        &Header::default(),
        &claim,
        &key,
    )
        .unwrap();

    let result = validate_token(&token, secret);

    assert!(result.is_err());
}