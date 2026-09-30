use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};

use serde::{Deserialize, Serialize};
use sqlx::types::chrono;
use crate::state::AppState;
use chrono::NaiveDateTime;

#[derive(Serialize)]
pub struct DashboardResponse{
    pub summary: DashboardSummary,
    pub attack_types:AttackTypeStats,
    pub recent_alerts:Vec<RecentAlert>,
}

#[derive(Serialize,sqlx::FromRow)]
pub struct DashboardSummary{
    pub total_alerts:i64,
    pub high_risk:i64,
    pub medium_risk:i64,
    pub low_risk:i64,
}



#[derive(Serialize,sqlx::FromRow)]
pub struct AttackTypeStats{
    pub sql_injection:i64,
    pub xss:i64,
    pub path_traversal:i64,
    pub sensitive_file:i64,
}

#[derive(Serialize,sqlx::FromRow)]
pub struct RecentAlert{
    pub id:i32,
    pub method:String,
    pub path:String,
    pub attack_type:String,
    pub risk:String,
    pub client_ip:Option<String>,
    pub timestamp:String,

}



#[derive(Deserialize)]
pub struct AlertFilter {
    pub risk: Option<String>,
    pub attack_type: Option<String>,
    pub method: Option<String>,
    pub time_range:Option<String>,
    pub from:Option<String>,
    pub to:Option<String>,
    pub sort:Option<String>,
    pub page:Option<i32>,
    pub limit:Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AlertResponse {
    pub id: i32,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub query: Option<String>,
    pub request_body: Option<String>,
    pub attack_type: String,
    pub risk: String,
    pub client_ip: Option<String>,
    pub timestamp: String,

}


#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AlertStats {
    pub total_alerts: i64,
    pub high_risk: i64,
    pub medium_risk: i64,
    pub low_risk: i64,
    pub sql_injection: i64,
    pub xss: i64,
    pub path_traversal: i64,
    pub sensitive_file: i64,
}

pub async fn get_alert_stats(
    State(state): State<AppState>,
) -> Result<Json<AlertStats>, StatusCode> {

    let stats = sqlx::query_as::<_, AlertStats>(
        r#"
        SELECT
            COUNT(*) AS total_alerts,

            COUNT(*) FILTER (
                WHERE risk = 'High'
            ) AS high_risk,

            COUNT(*) FILTER (
                WHERE risk = 'Medium'
            ) AS medium_risk,

            COUNT(*) FILTER (
                WHERE risk = 'Low'
            ) AS low_risk,

            COUNT(*) FILTER (
                WHERE attack_type = 'SqlInjection'
            ) AS sql_injection,

            COUNT(*) FILTER (
                WHERE attack_type = 'Xss'
            ) AS xss,

            COUNT(*) FILTER (
                WHERE attack_type = 'PathTraversal'
            ) AS path_traversal,

            COUNT(*) FILTER (
                WHERE attack_type = 'SensitiveFile'
            ) AS sensitive_file

        FROM alerts
        "#,
    )
        .fetch_one(&state.db_pool)
        .await
        .map_err(|error| {
            eprintln!("Failed to fetch alert stats: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(stats))
}


pub async fn get_alert(
    State(state): State<AppState>,
    Query(filter): Query<AlertFilter>,
) -> Result<Json<Vec<AlertResponse>>, StatusCode> {

    let from_time = match filter.from {
        Some(value) => Some(
            NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%S")
                .map_err(|error| {
                    eprintln!("Invalid from datetime: {}", error);
                    StatusCode::BAD_REQUEST
                })?
        ),
        None => None,
    };

    let to_time = match filter.to {
        Some(value) => Some(
            NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%S")
                .map_err(|error| {
                    eprintln!("Invalid to datetime: {}", error);
                    StatusCode::BAD_REQUEST
                })?
        ),
        None => None,
    };
    let  page = filter.page.unwrap_or(1);
    let limit = filter.limit.unwrap_or(10);

    if page <1{
        return Err(StatusCode::BAD_REQUEST);
    }
    if limit <1 || limit > 100{
        return Err(StatusCode::BAD_REQUEST);
    }

    let offset = (page - 1)* limit;

    let alerts = sqlx::query_as::<_, AlertResponse>(
        r#"
        SELECT
            id,
            method,
            path,
            user_agent,
            query,
            request_body,
            attack_type,
            risk,
            client_ip,
            timestamp::text AS timestamp
        FROM alerts
        WHERE ($1 IS NULL OR LOWER(risk) = LOWER($1))
          AND ($2 IS NULL OR LOWER(attack_type) = LOWER($2))
          AND ($3 IS NULL OR LOWER(method) = LOWER($3))

          AND (
              $4 IS NULL
              OR (
                  $4 = 'last_24_hours'
                  AND timestamp >= NOW() - INTERVAL '24 hours'
              )
              OR (
                  $4 = 'last_7_days'
                  AND timestamp >= NOW() - INTERVAL '7 days'
              )
              OR (
                  $4 = 'last_30_days'
                  AND timestamp >= NOW() - INTERVAL '30 days'
              )
          )

          AND ($5 IS NULL OR timestamp >= $5)
          AND ($6 IS NULL OR timestamp <= $6)

        ORDER BY
            CASE
                WHEN $7 = 'asc' THEN timestamp
            END ASC,
            CASE
                WHEN $7 = 'desc' OR $7 IS NULL THEN timestamp
            END DESC

           LIMIT $8
            OFFSET $9

        "#,
    )
        .bind(filter.risk)
        .bind(filter.attack_type)
        .bind(filter.method)
        .bind(filter.time_range)
        .bind(from_time)
        .bind(to_time)
        .bind(filter.sort)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|error| {
            eprintln!("Failed to fetch alerts: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(alerts))
}




pub async fn get_alert_by_id(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<AlertResponse>, StatusCode> {

    let alert = sqlx::query_as::<_, AlertResponse>(
        r#"
        SELECT
            id,
            method,
            path,
            user_agent,
            query,
            request_body,
            attack_type,
            risk,
            client_ip,
            timestamp::text AS timestamp
        FROM alerts
        WHERE id = $1
        "#,
    )
        .bind(id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|error| {
            eprintln!("Failed to fetch alert: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match alert{
        Some(alert)=>Ok(Json(alert)),
        None =>Err(StatusCode::NOT_FOUND),
    }
}


    pub async fn get_dashboard(
        State(state): State<AppState>,
    ) -> Result<Json<DashboardResponse>, StatusCode> {

        let summary = sqlx::query_as::<_, DashboardSummary>(
            r#"
        SELECT
            COUNT(*) AS total_alerts,

            COUNT(*) FILTER (
                WHERE risk = 'High'
            ) AS high_risk,

            COUNT(*) FILTER (
                WHERE risk = 'Medium'
            ) AS medium_risk,

            COUNT(*) FILTER (
                WHERE risk = 'Low'
            ) AS low_risk

        FROM alerts
        "#,
        )
            .fetch_one(&state.db_pool)
            .await
            .map_err(|error| {
                eprintln!("Failed to fetch dashboard summary: {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let attack_types = sqlx::query_as::<_, AttackTypeStats>(
            r#"
        SELECT
            COUNT(*) FILTER (
                WHERE attack_type = 'SqlInjection'
            ) AS sql_injection,

            COUNT(*) FILTER (
                WHERE attack_type = 'Xss'
            ) AS xss,

            COUNT(*) FILTER (
                WHERE attack_type = 'PathTraversal'
            ) AS path_traversal,

            COUNT(*) FILTER (
                WHERE attack_type = 'SensitiveFile'
            ) AS sensitive_file

        FROM alerts
        "#,
        )
            .fetch_one(&state.db_pool)
            .await
            .map_err(|error| {
                eprintln!("Failed to fetch attack type stats: {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let recent_alerts = sqlx::query_as::<_, RecentAlert>(
            r#"
        SELECT
            id,
            method,
            path,
            attack_type,
            risk,
            client_ip,
            timestamp::text AS timestamp
        FROM alerts
        ORDER BY id DESC
        LIMIT 5
        "#,
        )
            .fetch_all(&state.db_pool)
            .await
            .map_err(|error| {
                eprintln!("Failed to fetch recent alerts: {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        Ok(Json(DashboardResponse {
            summary,
            attack_types,
            recent_alerts,
        }))
}