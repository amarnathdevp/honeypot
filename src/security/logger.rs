
use sqlx::PgPool;
use crate::models::alert::Alert;
use crate::models::request::RequestInfo;



pub async  fn logger_alert(

    db:&PgPool,
    request: &RequestInfo,
    alert: &Alert
   )->Result<(), sqlx::Error>
{

    println!("AlertMessage");
    println!("Method{}",request.method);
    println!("Path{}",request.path);
    println!("Client_ip{}",request.client_ip);
    println!("user-agent:{}",request.user_agent);
    println!("alert{}",alert.attack_type);
    println!("Risk{}",alert.risk);


    sqlx::query(r#"
       INSERT INTO alerts
            (method, path, user_agent, query, request_body, attack_type, risk, client_ip)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,

    )

        .bind(&request.method)
        .bind(&request.path)
        .bind(&request.user_agent)
        .bind(&request.query)
        .bind(&request.request_body)
        .bind(&alert.attack_type)
        .bind(&alert.risk)
        .bind(&request.client_ip)
        .execute(db)
        .await?;

    println!("Alert saved to database");
    Ok(())

}
