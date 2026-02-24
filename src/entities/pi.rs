use crate::entities::user::User;
use crate::entities::helper_decryption::HelperDecryptionUser;
use ark_bls12_381::{G1Projective, G2Projective};

use ark_ff::Field; 

pub struct PiUser {
    pub pi_0: Vec<G1Projective>,
    pub pi_1: Vec<G1Projective>,
    pub pi_n_1: G2Projective,
    pub pi_n_2: G1Projective,
    pub pi_n_3: G1Projective,
    pub pi_n_4: G1Projective,
}

impl PiUser {
    pub fn new(user: &User, hsk: &HelperDecryptionUser) -> Self {        
        let sk_inv = user
            .sk
            .x
            .inverse()
            .expect("Secret key should not be zero");
        let mut pi_0: Vec<G1Projective> = Vec::new();
        let mut pi_1: Vec<G1Projective> = Vec::new();
        
        for i in 0..hsk.hsk_0.len() {
            // In the unwrapped protocol, pi = sk^-1 * hsk 
            // We multiply the Group Element by the Scalar Inverse 
            let pi_0_i = hsk.hsk_0[i] * sk_inv; 
            pi_0.push(pi_0_i);

            let pi_1_i = hsk.hsk_1[i] * sk_inv; 
            pi_1.push(pi_1_i);
        }
        let pi_n_1 = hsk.hsk_n_1 * sk_inv;
        let pi_n_2 = hsk.hsk_n_2 + hsk.hsk_n_3 * sk_inv;
        let pi_n_3 = hsk.hsk_n_4 * sk_inv;
        let pi_n_4 = hsk.hsk_n_5 * sk_inv;
        PiUser { 
            pi_0,
            pi_1,
            pi_n_1,
            pi_n_2,
            pi_n_3,
            pi_n_4,
         }
        
    }
}
