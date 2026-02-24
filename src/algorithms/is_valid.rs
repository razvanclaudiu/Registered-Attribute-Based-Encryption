use ark_ec::pairing::Pairing;
use ark_bls12_381::Bls12_381;

use crate::entities::keys::PublicKey;
use crate::entities::crs::CRS;

pub fn is_valid(crs: &CRS, pk_i: &PublicKey) -> bool {
    // The public key must contain [sk] followed by [sk * tau^1...m]
    // Length should match the m powers plus the base
    if pk_i.len() != crs.g1_powers.len() + 1 {
        return false;
    }

    let pk_i_0 = pk_i.get(0);

    // Check relationship: e([sk]_1, [tau^j]_2) == e([sk * tau^j]_1, [1]_2)
    for j in 0..crs.g2_powers.len() {
        // Left Hand Side: [pk_i,0]_1 ∘ [tau^{j+1}]_2
        let lhs = Bls12_381::pairing(pk_i_0, crs.g2_powers[j]);
        
        // Right Hand Side: [pk_i,j+1]_1 ∘ [1]_2
        let rhs = Bls12_381::pairing(pk_i.get(j + 1), crs.g2);

        if lhs != rhs {
            return false;
        }
    }

    true
}