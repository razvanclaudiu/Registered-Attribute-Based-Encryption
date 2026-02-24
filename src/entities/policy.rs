use serde::{Deserialize, Serialize}; 

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Literal {
    pub attribute_name: String,
    pub b: bool, // true = 1, false = 0
}

impl Literal {
    pub fn new(name: &str, val: bool) -> Self {
        Self {
            attribute_name: name.to_string(),
            b: val,
        }
    }
}

// A Clause is a disjunction (OR) of literals
pub type Clause = Vec<Literal>;

// A Policy is a conjunction (AND) of clauses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub clauses: Vec<Clause>,
}

impl Policy {
    pub fn new(clauses: Vec<Clause>) -> Self {
        Self { clauses }
    }

}