// IIP Gadget Structure
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ff::Field;
use ark_std::vec::Vec;
use ark_std::Zero;
use ark_ec::pairing::Pairing;

use crate::entities::crs::CRS;
use crate::entities::master_public_key::MasterPublicKey;
use crate::entities::user::User;
use crate::utils::polynoms::{get_lagrange_poly, get_vanish_poly};
use crate::entities::helper_decryption::HelperDecryptionUser;

pub struct IIPGadget;

impl IIPGadget {

    /// Computes {[s * tau^j]_1} which serves as the R-ABE Public Key elements.
    pub fn aux_gen(crs: &CRS, sk: Fr) -> Vec<G1Projective> {
        let mut aux = Vec::with_capacity(crs.g1_powers.len() + 1);
        
        aux.push(crs.g1 * sk);
        
        // The powers: [sk * tau^j]_1 for j=1..m
        for g1_pow in &crs.g1_powers {
            aux.push(*g1_pow * sk);
        }
        
        aux
    }

    pub fn digest(crs: &CRS, omega: &Vec<Fr>, users: &Vec<User>) -> (G1Projective, G2Projective) {
        let mut acc_scalar = Fr::zero();
        for i in 0..users.len() {
            // C = [Σ sk_i * L_i(tau)]_1
            acc_scalar += users[i].sk.x * get_lagrange_poly(omega, i, crs.tau);
        }
        let c = crs.g1 * acc_scalar;

        // U = [Z_Ω(tau)]_2
        let u = crs.g2 * get_vanish_poly(omega, crs.tau);

        (c, u)
    }

    pub fn prove(
        crs: &CRS,
        omega: &Vec<Fr>,
        users: &Vec<User>,
        user_index: usize,
    ) -> (G2Projective, G1Projective, G1Projective, G1Projective, G1Projective) {
        let lagrange_poly = get_lagrange_poly(&omega, user_index, crs.tau);
        let vanishing_poly_omega = get_vanish_poly(&omega, crs.tau);

        let hsk_n_1 = crs.g2 * lagrange_poly;
        let hsk_n_2 =crs.g1 * ((lagrange_poly * lagrange_poly - lagrange_poly) / vanishing_poly_omega);

        let mut scalar_hsk_n_3 = Fr::zero();
        for (j, _) in users.iter().enumerate() {
            if j != user_index {
                let lagrange_poly_j = get_lagrange_poly(&omega, j, crs.tau);
                scalar_hsk_n_3 += users[j].sk.x * ((lagrange_poly * lagrange_poly_j)/ vanishing_poly_omega);
            }
        }
        let hsk_n_3 = crs.g1 * scalar_hsk_n_3 ;

        let lagrange_poly_at_0 = get_lagrange_poly(&omega, user_index, Fr::from(0u64));
        let hsk_n_4 = crs.g1 * ((lagrange_poly - lagrange_poly_at_0) / crs.tau);
        let hsk_n_5 = crs.g1 * (lagrange_poly - lagrange_poly_at_0);

        (hsk_n_1, hsk_n_2, hsk_n_3, hsk_n_4, hsk_n_5)
    }

    pub fn verify(mpk: &MasterPublicKey, hsk_user: &HelperDecryptionUser, user: &User, omega: &Vec<Fr>, crs: &CRS) -> bool{
        let inv_sk = user.sk.x.inverse().unwrap();
        let lagrange_poly_0 = get_lagrange_poly(omega, user.id as usize - 1, Fr::from(0u64));
        // left = e(C, sk^(-1) * hsk_n_1) 
        let g2_element = hsk_user.hsk_n_1 * inv_sk;
        let left = Bls12_381::pairing(mpk.c, g2_element) ;


        let lagrange_poly = get_lagrange_poly(omega, user.id as usize - 1, crs.tau);
        

        // right = e([1]1, [1]2) + e(hsk_n_2 + sk^(-1) * hsk_n_3, U) + e(hsk_n_4, [tau]2)
        let right = crs.gt * lagrange_poly_0 + Bls12_381::pairing(hsk_user.hsk_n_2 + hsk_user.hsk_n_3 * inv_sk, mpk.u) + Bls12_381::pairing(hsk_user.hsk_n_4, crs.g2_powers[0]);
        let vanishing_poly_omega = get_vanish_poly(omega, crs.tau);
        let mut sum_hsk_3 = Fr::zero();
        for (j, _) in omega.iter().enumerate() {
            if j != (user.id as usize - 1) {
                let lagrange_poly_j = get_lagrange_poly(omega, j, crs.tau);
                sum_hsk_3 += (user.sk.x * (lagrange_poly * lagrange_poly_j)) / vanishing_poly_omega;
            }
        }
    
        if left != right {
            // println!("k + 1 relationship is NOT valid for user ID: {}", user.id);
            return false;
        }


        let g2_element = crs.g2_powers[0];
        let left = Bls12_381::pairing(hsk_user.hsk_n_4, g2_element);

        let g1_element = hsk_user.hsk_n_5;
        let right = Bls12_381::pairing(g1_element, crs.g2);

        if left != right {
            // println!("k + 2 relationship is NOT valid for user ID: {}", user.id);
            return false;
        } 
     true
    }
}