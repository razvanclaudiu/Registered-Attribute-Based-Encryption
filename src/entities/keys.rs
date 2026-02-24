use ark_bls12_381::{Fr, G1Projective};
 
pub struct SecretKey {
    pub x: Fr,
}

pub struct PublicKey {
    pub elements: Vec<G1Projective>,
}

impl PublicKey {
    //get element by index
    pub fn get(&self, index: usize) -> G1Projective {
        self.elements[index].into()
    }
    pub fn len(&self) -> usize {
        self.elements.len()
    }
}
