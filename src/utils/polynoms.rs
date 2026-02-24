use ark_bls12_381::Fr;
use ark_ff::{Field, One};
use ark_std::vec::Vec;


// Implements Lagrange Interpolation Polynomial at index 
pub fn get_lagrange_poly(domain: &Vec<Fr>, i: usize, coef: Fr) -> Fr {

    let mut product = Fr::one();
    for j in 0..domain.len() {
        if i != j {
            // product *= (coef - domain[j]) / (domain[i] - domain[j]);
            let numerator = coef - domain[j];
            let denominator = domain[i] - domain[j];
            product *= numerator * denominator.inverse().unwrap();
        }
    }
    product
}

// Implements Vanishing Polynomial over a given domain at point tau
pub fn get_vanish_poly(domain: &Vec<Fr>, tau: Fr) -> Fr {
    let mut poly = Fr::one();
    for w in domain {
        // Multiply the current polynomial by the new term
        poly = poly * (tau - w);
    }
    poly
}