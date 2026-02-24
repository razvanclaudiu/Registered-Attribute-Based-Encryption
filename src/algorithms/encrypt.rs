use ark_ff::UniformRand;
use ark_bls12_381::Fr;
use ark_std::vec::Vec;
use std::ops::{Mul, Add};
use ark_std::Zero;

use crate::entities::{
    ciphertext::{self, Ciphertext}, crs::CRS, master_public_key::MasterPublicKey, policy::Policy
};


fn generate_s_vector(k: usize) -> Vec<Fr> {
    let mut rng = ark_std::test_rng();
    // Generate a vector of length k + 2
    let s: Vec<Fr> = (0..k + 2)
        .map(|_| Fr::rand(&mut rng))
        .collect();
    s
}


pub fn encrypt(mpk: &MasterPublicKey, policy: &Policy, msg: Fr, crs: &CRS) -> Ciphertext {
    // Implementation of the encryption algorithm
    let mut ciphertext_obj = Ciphertext::new(policy.clone());

    for clause in &policy.clauses { 
        let k = clause.len();
        let s = generate_s_vector(k);
        // sT * A_alpha we will create to result vectors c1 and c2
        let mut c1: Vec<ark_bls12_381::G1Projective> = Vec::new();
        let mut c2: Vec<ark_bls12_381::G2Projective> = Vec::new();
        let c1_zero = ark_bls12_381::G1Projective::zero();
        let c2_zero = ark_bls12_381::G2Projective::zero();
        for i in 0..k + 4 {
            if i == k  {
                // 0 to G2 
                c2.push(c2_zero);
                let mut sum_attr = ark_bls12_381::G1Projective::zero();
                for j in 0..k {
                    // s[i] * A_alpha[i][j], A_alpha[i][j] = mpk.U_eff[attr]
                    let c1_i;
                    if clause[j].b{
                        c1_i = mpk.u_list_0[mpk.u_eff.iter().position(|n| n == clause[j].attribute_name.as_str()).unwrap()].mul(s[j]);
                    }
                    else {
                        c1_i = mpk.u_list_1[mpk.u_eff.iter().position(|n| n == clause[j].attribute_name.as_str()).unwrap()].mul(s[j]);
                    }
                    if sum_attr == ark_bls12_381::G1Projective::zero() {
                        sum_attr = c1_i;
                    } else {
                        sum_attr = sum_attr.add(&c1_i);
                    }
                }
                let c1_i = mpk.c.mul(s[k]);
                sum_attr = sum_attr.add(&c1_i);
                c1.push(sum_attr);
            } else {
                // 0 to G1
                c1.push(c1_zero);
                if i < k {
                    // s[i] * A_alpha[i][i], A_alpha[i][i] = mpk.u
                    let neg_z_omega = - mpk.u;
                    let c2_i = neg_z_omega.mul(s[i]); 
                    c2.push(c2_i);
                } else if i == k + 1 {
                    let neg_z_omega = - mpk.u;
                    let c2_i = neg_z_omega.mul(s[k]); 
                    c2.push(c2_i);
                }
                else if i == k + 2 {
                    let c2_i = crs.g2_powers[0].mul(s[k]);
                    let c2_j = crs.g2_powers[1].mul(s[k+1]);
                    c2.push(c2_i.add(&c2_j));
                } else if i == k + 3 {
                    let c2_i = - crs.g2.mul(s[k+1]);
                    c2.push(c2_i);
                }

            }
        }

        //s[0] * [1]T
        let mut c3 = crs.gt.mul(s[0]);
        let msg_as_group_element = crs.gt.mul(msg);

        c3 = c3.add(msg_as_group_element);
        let clause_ciphertext = ciphertext::ClauseCiphertext {
            c1,
            c2,
            c3,
        };
        ciphertext_obj.push(clause_ciphertext);
    }
    ciphertext_obj
}