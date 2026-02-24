use ark_bls12_381::Fr;

use crate::entities::crs::CRS;
use crate::entities::policy::Policy;
use crate::entities::user::{User};
use crate::algorithms::is_valid::is_valid;
use crate::entities::master_public_key::MasterPublicKey;
use crate::entities::helper_decryption::HelperDecryptionList;
use crate::algorithms::setup::setup;
use crate::algorithms::kgen::kgen;
use crate::algorithms::aggregate::aggregate;
use crate::algorithms::decrypt::decrypt;
use crate::utils::generate_omega::generate_omega;


pub struct WE {
    pub crs: CRS,
    pub omega: Vec<Fr>,
    pub mpk: MasterPublicKey,
    pub hsk: HelperDecryptionList,
}


impl WE {
    /// Initialize the framework with shared CRS and Omega
    pub fn new(m: usize) -> Self {
        let crs = setup(m);
        let omega = generate_omega(m);

        Self {
            crs,
            omega,
            mpk: MasterPublicKey::new_empty(),
            hsk: HelperDecryptionList::new(),
        }
    }

    /// Orchestrates key generation and validation for a list of users
    pub fn process_users(&self, users: &mut Vec<User>) {
        for user in users.iter_mut() {
            // 1. Generate keys locally for the user
            let (pk, sk) = kgen(&self.crs);
            user.pk = pk;
            user.sk = sk;

            // Validate the Public Key immediately
            // This checks e([sk]_1, [tau^j]_2) == e([sk*tau^j]_1, [1]_2)
            let is_key_legit = is_valid(&self.crs, &user.pk);
            
            if is_key_legit {
                println!("User {} verified successfully.", user.id);
            } else {
                eprintln!("User {} failed public key validation!", user.id);
            }
        }
    }

    pub fn initialize_aggregate(&mut self, users: &Vec<User>) {
        (self.hsk, self.mpk) = aggregate(&self.crs, &users, &self.omega);
        println!("Aggregate Master Public Key and Helper Decryption Keys generated.");
    }

    pub fn simulate_encrypt_decrypt(&self, users: &Vec<User>, policy: &Policy, msg: Fr) {
        let ct = crate::algorithms::encrypt::encrypt(&self.mpk, policy, msg, &self.crs);
        //println!("Ciphertext generated: {:?}", ct);

        let pairing_msg = self.crs.gt * msg;
        //print!("Pairing message in GT: {:?}\n", pairing_msg);
        
        for user in users {
            let decrypted_msg = decrypt(&ct, user, self.hsk.get(user.id).unwrap(), &self.crs, &self.mpk, &self.omega);
            match decrypted_msg {
                Some(m) => {
                    if m == pairing_msg {
                        println!("User ID: {} successfully decrypted the message.", user.id);
                    } else {
                        println!("User ID: {} failed to decrypt the message correctly.", user.id);
                    }
                },
                None => {
                    println!("User ID: {} could not decrypt the message.", user.id);
                }
            }
        }
    }

    
}