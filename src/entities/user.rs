use serde::Deserialize;
use crate::entities::keys::{PublicKey, SecretKey};

#[derive(Deserialize)]
pub struct RawUser {
    pub user_id: u32,
    pub attributes: Vec<String>,
}

pub struct User {
    pub id: u32,
    pub attributes_list: Vec<String>,
    pub sk: SecretKey,
    pub pk: PublicKey,
}
