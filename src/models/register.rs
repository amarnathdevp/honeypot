use serde::Deserialize;
#[derive(Debug, Deserialize)]

pub struct RegisterRequest{
    pub username:String,
    pub password:String,
}