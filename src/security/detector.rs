use crate::models::alert::AttackType;
use crate::models::request::RequestInfo;

use crate::security::rules::{
 SENSITIVE_PATHS,
 PATHS_TRAVERSAL_PATTERNS,
 XSS_PATTERNS,
 SQL_INJECTION_PATTERNS,
};


fn normalize_input(input:&str)-> String{
 input
     .split_whitespace()
     .collect::<Vec<&str>>()
     .join(" ")
     .to_lowercase()
}
pub fn detect(request: &RequestInfo) -> Option<AttackType> {

 let decode_body = urlencoding::decode(&request.request_body)
     .unwrap_or_else(|_| request.request_body.clone().into())
     .to_string();


 let input = match &request.query {
  Some(query) => {
   let decoded_query = urlencoding::decode(query)
       .unwrap_or_else(|_| query.clone().into())
       .to_string();


   format!("{}?{} {}",
           request.path,
           decoded_query,
           request.request_body
   )

  }
  None => {
   format!(
    "{} {}",

   request.path,
    decode_body
   )
  },

 };

 let input = normalize_input(&input);

 // Sensitive file
 if SENSITIVE_PATHS.contains(&request.path.as_str()) {
  return Some(AttackType::SensitiveFile);
 }

 // Path Traversal
 if PATHS_TRAVERSAL_PATTERNS
     .iter()
     .any(|pattern| input.contains(pattern))
 {
  return Some(AttackType::PathTraversal);
 }

 // XSS
 if XSS_PATTERNS
     .iter()
     .any(|pattern| input.to_lowercase().contains(&pattern.to_lowercase()))
 {
  return Some(AttackType::Xss);
 }

 // SQL Injection
 if SQL_INJECTION_PATTERNS
     .iter()
     .any(|pattern| input.to_lowercase().contains(&pattern.to_lowercase()))
 {
  return Some(AttackType::SqlInjection);
 }

 None
}