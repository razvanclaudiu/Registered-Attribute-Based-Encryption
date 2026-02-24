use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_std::Zero;
use ark_bls12_381::Fr;

use crate::{entities::{ciphertext::Ciphertext, crs::CRS, helper_decryption::HelperDecryptionUser, master_public_key::MasterPublicKey, user::User}, gadgets::{iip::IIPGadget, zero_check::ZeroCheckGadget}};

pub fn decrypt(ct: &Ciphertext, user: &User, hsk: &HelperDecryptionUser, crs: &CRS, mpk: &MasterPublicKey, omega: &Vec<Fr>) -> Option<PairingOutput<Bls12_381>> {
    if !ZeroCheckGadget::verify(mpk, hsk, user, &ct.policy) && !IIPGadget::verify(mpk, hsk, user, omega, crs) {
        return None;
    } 

    let pi_user = crate::entities::pi::PiUser::new(user, hsk);

    for (i, clause) in ct.policy.clauses.iter().enumerate() {
        let mut satisfied = true;
        let k = clause.len();
        let mut sum = PairingOutput::<Bls12_381>::zero();
        let ct = &ct.rows[i];
        for j in  0..clause.len() {
            if (clause[j].b && user.attributes_list.contains(&clause[j].attribute_name)) || (!clause[j].b && !user.attributes_list.contains(&clause[j].attribute_name)) {
                let attribute_index = mpk.u_eff.iter().position(|n| n == clause[j].attribute_name.as_str()).unwrap();
                let pairing_result = if clause[j].b {
                    Bls12_381::pairing(pi_user.pi_0[attribute_index], ct.c2[j])
                } else {
                    Bls12_381::pairing(pi_user.pi_1[attribute_index], ct.c2[j])
                };

                sum += pairing_result;
            } else {
               satisfied = false;
               break;
           }
        }
        if !satisfied {
            continue;
        }
        let pairing_n1 = Bls12_381::pairing(ct.c1[k], pi_user.pi_n_1, );
        let pairing_n2 = Bls12_381::pairing(pi_user.pi_n_2, ct.c2[k + 1]);
        let pairing_n3 = Bls12_381::pairing(pi_user.pi_n_3, ct.c2[k + 2]);
        let pairing_n4 = Bls12_381::pairing(pi_user.pi_n_4, ct.c2[k + 3]);

        sum += pairing_n1 + pairing_n2 + pairing_n3 + pairing_n4;

        let msg = ct.c3 - sum;
        //print!("user {} decrypted message: {:?}\n", user.id, msg);
        return Some(msg);
    }
    

    None
}
