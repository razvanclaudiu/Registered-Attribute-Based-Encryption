use ark_bls12_381::{G1Projective, G2Projective};
pub struct HelperDecryptionUser {
    pub id: u32,
    pub hsk_0: Vec<G1Projective>,
    pub hsk_1: Vec<G1Projective>,
    pub hsk_n_1: G2Projective,
    pub hsk_n_2: G1Projective,
    pub hsk_n_3: G1Projective,
    pub hsk_n_4: G1Projective,
    pub hsk_n_5: G1Projective,
}

impl HelperDecryptionUser {
    // constructor create empty helper decryption user
    pub fn new(id: u32) -> Self {
        HelperDecryptionUser {
            id,
            hsk_0: Vec::new(),
            hsk_1: Vec::new(),
            hsk_n_1: G2Projective::default(),
            hsk_n_2: G1Projective::default(),
            hsk_n_3: G1Projective::default(),
            hsk_n_4: G1Projective::default(),
            hsk_n_5: G1Projective::default(),
        }
    }
}

pub struct HelperDecryptionList {
    pub helpers: Vec<HelperDecryptionUser>,
}

impl HelperDecryptionList {
    pub fn new() -> Self {
        HelperDecryptionList { helpers: Vec::new() }
    }

    pub fn add_helper(&mut self, helper: HelperDecryptionUser) {
        self.helpers.push(helper);
    }

    pub fn get(&self, id: u32) -> Option<&HelperDecryptionUser> {
        self.helpers.iter().find(|h| h.id == id)
    }
}