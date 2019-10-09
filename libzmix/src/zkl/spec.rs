pub struct ProofSpec {
    pub attribute_count: u32,
    pub disclosed_attributes: Vec<DisclosedAttribute>,
    pub clauses: Vec<ProofSpecClauseType>,
}

/// Used for crossing ffi boundary like 'C'
pub struct ProofSpecBuilder {
    attribute_count: u32,
    disclosed_attributes: Vec<DisclosedAttribute>,
    clauses: Vec<ProofSpecClauseType>,
}

impl ProofSpecBuilder {
    pub fn new() -> ProofSpecBuilder {
        ProofSpecBuilder {
            attribute_count: 0,
            disclosed_attributes: Vec::new(),
            clauses: Vec::new(),
        }
    }

    pub fn add_clause(&mut self, clause: ProofSpecClauseType) {
        self.clauses.push(clause);
    }

    pub fn add_disclosed_attribute(&mut self, index: u32, value: &str) {
        self.disclosed_attributes.push(DisclosedAttribute {
            index,
            value: value.to_owned(),
        });
    }

    pub fn set_attribute_count(&mut self, attribute_count: u32) {
        self.attribute_count = attribute_count;
    }

    pub fn finalize(self) -> ProofSpec {
        ProofSpec {
            attribute_count: self.attribute_count,
            disclosed_attributes: self.disclosed_attributes,
            clauses: self.clauses,
        }
    }
}

pub enum ProofSpecClauseType {
    Credential,
    Interval,
    SetMembership,
    VerifiableEncryption,
    Nym,
}

pub struct DisclosedAttribute {
    pub index: u32,
    pub value: String,
}

pub struct Witness {
    statement_witnesses: Vec<StatementWitness>,
}

pub enum StatementWitness {
    SignatureBBS(SignatureBBSWitness),
}

pub struct SignatureBBSWitness {
    // TODO: This needs the messages as well.
    a: Vec<Vec<u8>>,
    e: Vec<Vec<u8>>,
    s: Vec<Vec<u8>>,
}

// TODO: Self attested attributes

// TODO: Signatures should use Transcript as the challenge for Bulletproofs cannot be separated from other part of the proof
