use crate::models::alert::AttackType;

pub fn score(attack: &AttackType)->&'static str{
    match attack {
        AttackType::SensitiveFile => "High",
        AttackType::PathTraversal => "High",
        AttackType::Xss =>"Medium",
        AttackType::SqlInjection => "High"
    }
}