use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::thread_rng;

use crate::entities::crs::CRS;
use crate::entities::keys::{PublicKey, SecretKey};
use crate::gadgets::iip::IIPGadget;

pub fn kgen(crs: &CRS) -> (PublicKey, SecretKey) {
    let mut rng = thread_rng();
    
    // Generate a random secret key x
    let x: Fr = Fr::rand(&mut rng);

    // Call IIP Gadget to generate the public elements (hints)
    let pk_elements = IIPGadget::aux_gen(crs, x);

    let pk = PublicKey { elements: pk_elements };
    let sk = SecretKey { x };

    (pk, sk)
}