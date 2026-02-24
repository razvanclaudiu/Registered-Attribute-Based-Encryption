use ark_bls12_381::{G1Projective, G2Projective, Bls12_381};
use ark_ec::pairing::PairingOutput;
use crate::entities::policy::Policy;
#[derive(Debug, Clone)]
pub struct ClauseCiphertext {
    pub c1: Vec<G1Projective>,
    pub c2: Vec<G2Projective>,
    pub c3: PairingOutput<Bls12_381>,    
}

#[derive(Debug, Clone)]
pub struct Ciphertext {
    pub policy: Policy,
    pub rows: Vec<ClauseCiphertext>,      
}

// emptyy cyphertext for placeholder
impl Ciphertext {
    pub fn new(policy: Policy) -> Self {
        Ciphertext {
            policy,
            rows: Vec::new(),
        }
    }
    pub fn push(&mut self, clause_ct: ClauseCiphertext) {
        self.rows.push(clause_ct);
    }
}