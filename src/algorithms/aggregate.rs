
use std::collections::HashSet;
use ark_bls12_381::{Fr, G1Projective};

use crate::entities::crs::CRS;
use crate::entities::helper_decryption::{HelperDecryptionList, HelperDecryptionUser};
use crate::entities::master_public_key::MasterPublicKey;
use crate::entities::user::User;
use crate::gadgets::iip::IIPGadget;
use crate::gadgets::zero_check::ZeroCheckGadget;

fn get_attributes_set(users: &Vec<User>) -> Vec<String> {
    let mut set = HashSet::new();
    
    for user in users {
        for attr in &user.attributes_list {
            set.insert(attr.clone());
        }
    }

    set.into_iter().collect()
}

fn get_i0_i1(users: &Vec<User>, u_eff: &Vec<String>) -> (Vec<Vec<usize>>, Vec<Vec<usize>>){
        // create matrix of size |U_eff| x []
        let mut i_0: Vec<Vec<usize>> = Vec::new();
        let mut i_1: Vec<Vec<usize>> = Vec::new();
        for index in 0..u_eff.len() {
            i_0.push(Vec::new());
            i_1.push(Vec::new());
            for index_user in 0..users.len() {
                if users[index_user].attributes_list.contains(&u_eff[index]) {
                   i_0[index].push(index_user);
                } else {
                   i_1[index].push(index_user);
            }}
            println!("Attribute ID: {}: I_0: {:?}, I_1: {:?}", index, i_0[index], i_1[index]);   
        }
        (i_0, i_1)
}

fn get_commitment_set(i_0: &Vec<Vec<usize>>, i_1: &Vec<Vec<usize>>, crs: &CRS, omega: &Vec<Fr>) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let mut commitment_set_0: Vec<G1Projective> = Vec::new();
        let mut commitment_set_1: Vec<G1Projective> = Vec::new();
        for index in 0..i_0.len() {
            
            let u_0= ZeroCheckGadget::digest(&i_0[index], crs, omega);
            commitment_set_0.push(u_0);

            let u_1 = ZeroCheckGadget::digest(&i_1[index], crs, omega);
            commitment_set_1.push(u_1);
            //println!("Attribute ID: {}: Commitment I_0: {:?}, Commitment I_1: {:?}", index, u_0, u_1);
        }
        (commitment_set_0, commitment_set_1)
    }

fn get_helper_decryption_list(i_0: &Vec<Vec<usize>>, i_1: &Vec<Vec<usize>>, users: &Vec<User>, crs: &CRS, omega: &Vec<Fr>) -> HelperDecryptionList{
    let mut hsk = HelperDecryptionList::new();
    for (i, user) in users.iter().enumerate() {
        let mut helper = HelperDecryptionUser::new(user.id);
        
        helper.hsk_0 = ZeroCheckGadget::prove(&i_0, i, crs, omega);
        helper.hsk_1 = ZeroCheckGadget::prove(&i_1, i, crs, omega);

        (helper.hsk_n_1, helper.hsk_n_2, helper.hsk_n_3, helper.hsk_n_4, helper.hsk_n_5) = IIPGadget::prove(crs, omega, users, i);

        hsk.add_helper(helper);
    }
    hsk
}

pub fn aggregate(crs: &CRS, users_list: &Vec<User>, omega: &Vec<Fr>) -> (HelperDecryptionList, MasterPublicKey){
    
    let u_eff = get_attributes_set(&users_list);

    let (i_0, i_1) = get_i0_i1(&users_list, &u_eff);
    // println!("I_0: {:?}, I_1: {:?}", i_0, i_1);
    
    let (u_list_0, u_list_1) = get_commitment_set(&i_0, &i_1, crs, &omega);
    
    let (c, u) = IIPGadget::digest(crs, &omega, &users_list);

    let helper_decryption_list = get_helper_decryption_list(&i_0, &i_1, &users_list, crs, &omega);
    let master_public_key = MasterPublicKey::new(
        c,
        u,
        u_list_1,
        u_list_0,
        u_eff
    );

    (helper_decryption_list, master_public_key)
 
}