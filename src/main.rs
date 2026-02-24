mod utils;
mod gadgets;
mod entities;
mod we;
mod algorithms;

use ark_bls12_381::{Fr};

use crate::{entities::policy::{Literal, Policy}, we::WE};

fn main() {
    println!("--------- Registered Attribute-Based Encryption Scheme ---------");
    println!(" ---------------------------------------------------------------");

    println!(" ---------------------------------------------------------------");
    let file_path = "D:\\Master\\SemProj\\Registered-Attribute-Based-Encryption\\registered-attribute-based-encryption\\registered_attribute_based_encryption\\src\\users_configs.json";
    let (mut users, m) = utils::read_json::read_json_from_file(file_path).unwrap();

    let mut we = WE::new(m as usize);
    println!("WE Gadget initialized successfully with {} slots!", m);
    println!(" ---------------------------------------------------------------");

    we.process_users(&mut users);
    
    we.initialize_aggregate(&users);

    let clause_1 = vec![
        Literal::new("role:user", true),
    ];
    // let clause_2 = vec![
    //     Literal::new("department:marketing", true),
    // ];
    let policy = Policy::new(vec![clause_1]);

    println!("Policy defined: {:?}", policy);
    println!(" ---------------------------------------------------------------");

    let msg = Fr::from(0u64);
    print!("Message to encrypt: {:?}\n", msg);  

    we.simulate_encrypt_decrypt(&users, &policy, msg);
    

}