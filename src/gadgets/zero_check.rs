use crate::entities::master_public_key::MasterPublicKey;
use crate::entities::policy::Policy;
use crate::entities::user::User;
use crate::utils::polynoms::get_vanish_poly;
use crate::entities::crs::CRS;
use crate::utils::polynoms::get_lagrange_poly;
use crate:: entities::helper_decryption::HelperDecryptionUser;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_bls12_381::{Bls12_381};

use std::ops::Mul;
pub struct ZeroCheckGadget;

impl ZeroCheckGadget {
    pub fn digest(i: &Vec<usize>, crs: &CRS, omega: &Vec<Fr>) -> G1Projective {
        let mut w: Vec<Fr> = Vec::new();
        for i in i.iter() {
            w.push(omega[*i]);
        }
    
        let u_0= crs.g1 * get_vanish_poly(&w, crs.tau);
        u_0
    }

    pub fn prove(i: &Vec<Vec<usize>>, index: usize, crs: &CRS, omega: &Vec<Fr>) ->  Vec<G1Projective> {
        let mut hsk_list: Vec<G1Projective> = Vec::new();
        for k in 0..i.len() {
            let mut w: Vec<Fr> = Vec::new();
            for j in i[k].iter() {
                w.push(omega[*j]);
            }
            
            let hsk_attr: ark_ec::short_weierstrass::Projective<ark_bls12_381::g1::Config> =crs.g1 * ((get_lagrange_poly(&omega, index, crs.tau) * get_vanish_poly(&w, crs.tau)/get_vanish_poly(&omega, crs.tau)));
            hsk_list.push(hsk_attr); 
        }
        hsk_list
        
    }

    pub fn verify(mpk: &MasterPublicKey, hsk_user: &HelperDecryptionUser, user: &User, policy: &Policy) -> bool {
        let inv_sk = user.sk.x.inverse().unwrap();
        let b_i = hsk_user.hsk_n_1.mul(inv_sk);

        for clause in &policy.clauses {
            let mut clause_satisfied = false;

            for attr in clause {
                let user_has_attr = user.attributes_list.contains(&attr.attribute_name);
                
                if attr.b == user_has_attr { 
                    clause_satisfied = true; 
                }

                let i = mpk.u_eff.iter().position(|n| n == &attr.attribute_name).unwrap();
                let (commitment, proof) = if !attr.b {
                    (mpk.u_list_0[i], hsk_user.hsk_0[i])
                } else {
                    (mpk.u_list_1[i], hsk_user.hsk_1[i])
                };

                let left = Bls12_381::pairing(commitment, b_i);
                let right = Bls12_381::pairing(proof.mul(inv_sk), mpk.u);

                if left != right {
                    // println!(" ---------------------------------------------------------------");
                    // println!("Hsk or mpk verification failed for clause {:?}", clause);
                    // println!(" ---------------------------------------------------------------");
                    return false;
                }
            }

            if !clause_satisfied { 
                // println!(" ---------------------------------------------------------------");
                // println!("User ID: {}: Does NOT satisfy the policy", user.id);
                // println!("Clause {:?} is NOT satisfied!", clause);
                // println!(" ---------------------------------------------------------------");
                return false;
            }
        }
        true
    }
}