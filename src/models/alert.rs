

pub struct Alert {
   pub attack_type:String,
    pub risk:String,
   

}


#[derive(Debug)]

pub enum AttackType{
    SensitiveFile,
    PathTraversal,
    Xss,
    SqlInjection,
}