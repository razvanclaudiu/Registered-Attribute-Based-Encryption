use std::fs::read_to_string;

use std::error::Error;
use ark_bls12_381::{ Fr};

use crate::entities::user::{User, RawUser};
use crate::entities::keys::{PublicKey, SecretKey};

use serde::Deserialize;

#[derive(Deserialize)]
struct UsersFile {
    user_count: usize,
    users: Vec<RawUser>,
}

// Read from a Json file M, the number of users, and the user data and attributes
// The funtion will return the list and the count of users
pub fn read_json_from_file(path: &str) -> Result<(Vec<User>, usize), Box<dyn Error>> {
    // Read raw JSON
    let data = read_to_string(path)?;

    // Deserialize into temporary container
    let raw: UsersFile = serde_json::from_str(&data)?;

    // Convert RawUser → User
    let users: Vec<User> = raw.users.into_iter().map(|u| {
        User {
            id: u.user_id,      
            attributes_list: u.attributes,
            sk: SecretKey { x: Fr::default() }, 
            pk: PublicKey { elements: vec![] },                
        }
    }).collect();

    Ok((users, raw.user_count))
}