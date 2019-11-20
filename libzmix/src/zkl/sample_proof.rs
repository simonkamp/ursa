use amcl_wrapper::field_elem::FieldElement;
use signatures::bbs::keys::PublicKey as BBSVerkey;
use signatures::bbs::pok_sig::{PoKOfSignature as PoKBBSSig, PoKOfSignatureProof as PoKBBSigProof};
use signatures::bbs::signature::Signature as BBSSig;
use signatures::ps::keys::{Params as PSParams, Verkey as PSVerkey};
use signatures::ps::pok_sig::{PoKOfSignature as PoKPSSig, PoKOfSignatureProof as PoKPSSigProof};
use signatures::ps::signature::Signature as PSSig;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub enum Statement {
    /*PoKSignatureBBS {
        pk: PublicKey,
        messages: Vec<Vec<u8>>,
    },*/
    PoKSignatureBBS(PoKSignatureBBS),
    PoKSignaturePS(PoKSignaturePS),
    /*Equality {

    },*/
    /*PublicEquality {
        // Equivalent to reveal message
    },*/
}

#[derive(Clone)]
pub struct PoKSignatureBBS {
    pk: BBSVerkey,
    // Messages being revealed.
    revealed_messages: HashMap<usize, FieldElement>,
}

#[derive(Clone)]
pub struct PoKSignaturePS {
    pk: PSVerkey,
    params: PSParams,
    // Messages being revealed.
    revealed_messages: HashMap<usize, FieldElement>,
}

#[derive(Clone)]
pub struct ProofSpec {
    //message_count: usize,
    pub statements: Vec<Statement>,
    // TODO: Implement iteration
}

#[derive(Clone)]
pub struct Witness {
    pub statement_witnesses: Vec<StatementWitness>,
    // TODO: Implement iteration
}

// TODO: Convert to same structure as `enum Statement`, struct for witness lives outside
#[derive(Clone)]
pub enum StatementWitness {
    //SignatureBBS(SignatureBBSWitness),
    SignaturePS {
        sig: PSSig,
        messages: Vec<FieldElement>,
    },
    SignatureBBS {
        sig: BBSSig,
        messages: Vec<FieldElement>,
    },
}

/*pub struct SignaturePSWitness {
    sig: PSSig,
    messages: Vec<FieldElement>
}*/

#[derive(Clone)]
pub enum StatementProof {
    //    SignatureBBS(SignatureBBSProof),
    //SignaturePSProof(SignaturePSProof),
    SignaturePSProof(SignaturePSProof),
    SignatureBBSProof(SignatureBBSProof),
}

#[derive(Clone)]
pub struct SignaturePSProof {
    pub proof: PoKPSSigProof,
}

#[derive(Clone)]
pub struct SignatureBBSProof {
    pub proof: PoKBBSigProof,
}

// TODO: Follow the Builder pattern like ProofSpecBuilder, add_clause, etc
impl ProofSpec {
    pub fn new() -> Self {
        Self {
            statements: Vec::<Statement>::new(),
        }
    }

    pub fn add_statement(&mut self, statement: Statement) {
        self.statements.push(statement)
    }
}

pub struct Proof {
    pub challenge: FieldElement,
    pub statement_proofs: Vec<StatementProof>,
}

pub trait ProofModule {
    // TODO: Rename
    fn get_hash_contribution(
        &mut self,
        //        statement: Statement,
        witness: StatementWitness,
        // TODO: Come back to blindings
        //blindings: Vec<FieldElement>,
        // TODO: Accepts errors too
        //) -> Result<(HashContribution, ProofModuleState), ZkLangError>;
        //    ) -> CommitmentContrib;       // TODO: Find a better name for CommitmentContrib, is "Commitment" ok?
    ) -> Vec<u8>;
    fn get_proof_contribution(
        //        state: ProofModuleState,
        &mut self,
        challenge: &FieldElement,
        // TODO: Accepts errors too
        //) -> Result<StatementProof, ZkLangError>;
    ) -> StatementProof;
    fn verify_proof_contribution(
        &self,
        challenge: &FieldElement,
        //        statement: Statement,
        proof: StatementProof,
        // TODO: Accepts errors too
        //    ) -> Result<HashContribution, ZkLangError>;
    ) -> bool;
}

pub struct PSSigProofModule {
    pok_sig: Option<PoKPSSig>,
    statement: PoKSignaturePS,
}

impl PSSigProofModule {
    pub fn new(statement: PoKSignaturePS) -> Self {
        // Question: Should the statement be stored in ProofModule?
        Self {
            pok_sig: None,
            statement,
        }
    }
}

impl ProofModule for PSSigProofModule {
    fn get_hash_contribution(
        &mut self,
        //        statement: Statement,
        witness: StatementWitness,
    ) -> Vec<u8> {
        let pok_sig = match witness {
            StatementWitness::SignaturePS { sig, messages } => {
                let indices = (&self.statement)
                    .revealed_messages
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<usize>>();
                PoKPSSig::init(
                    &sig,
                    &self.statement.pk,
                    &self.statement.params,
                    &messages,
                    None,
                    indices,
                )
                .unwrap()
            }
            _ => panic!(""),
        };
        let bytes = pok_sig.to_bytes();
        self.pok_sig = Some(pok_sig);
        /*match witness {
            StatementWitness::SignaturePS {
                sig,
                messages
            } => ()
        }
        match statement {
            Statement::PoKSignaturePS {
                pk: PSVerkey,
                params: PSParams,
                revealed_message_indices,
            } => (),
        }*/
        /*self.pok_sig = Some(
            PoKPSSig::init(sig, vk, params, messages, blindings, revealed_msg_indices).unwrap()
        );*/
        bytes
    }

    fn get_proof_contribution(&mut self, challenge: &FieldElement) -> StatementProof {
        // TODO: Is there a better way?
        let pok_sig = self.pok_sig.take().unwrap();
        let proof = pok_sig.gen_proof(&challenge).unwrap();
        StatementProof::SignaturePSProof(SignaturePSProof { proof })
    }

    fn verify_proof_contribution(
        &self,
        challenge: &FieldElement,
        //        statement: Statement,
        proof: StatementProof,
    ) -> bool {
        match proof {
            StatementProof::SignaturePSProof(proof) => proof
                .proof
                .verify(
                    &self.statement.pk,
                    &self.statement.params,
                    self.statement.revealed_messages.clone(),
                    challenge,
                )
                .unwrap(),
            _ => panic!(""),
        }
    }
}

pub struct BBSSigProofModule {
    pok_sig: Option<PoKBBSSig>,
    statement: PoKSignatureBBS,
}

impl BBSSigProofModule {
    pub fn new(statement: PoKSignatureBBS) -> Self {
        // Question: Should the statement be stored in ProofModule?
        Self {
            pok_sig: None,
            statement,
        }
    }
}

impl ProofModule for BBSSigProofModule {
    fn get_hash_contribution(
        &mut self,
        //        statement: Statement,
        witness: StatementWitness,
    ) -> Vec<u8> {
        let pok_sig = match witness {
            StatementWitness::SignatureBBS { sig, messages } => {
                let indices = (&self.statement)
                    .revealed_messages
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<usize>>();
                PoKBBSSig::init(&sig, &self.statement.pk, &messages, None, indices).unwrap()
            }
            _ => panic!("Match failed in get_hash_contribution"),
        };
        let bytes = pok_sig.to_bytes();
        self.pok_sig = Some(pok_sig);
        bytes
    }

    fn get_proof_contribution(&mut self, challenge: &FieldElement) -> StatementProof {
        // TODO: Is there a better way?
        let pok_sig = self.pok_sig.take().unwrap();
        let proof = pok_sig.gen_proof(&challenge).unwrap();
        StatementProof::SignatureBBSProof(SignatureBBSProof { proof })
    }

    fn verify_proof_contribution(
        &self,
        challenge: &FieldElement,
        //        statement: Statement,
        proof: StatementProof,
    ) -> bool {
        match proof {
            StatementProof::SignatureBBSProof(SignatureBBSProof { proof }) => proof
                .verify(
                    &self.statement.pk,
                    self.statement.revealed_messages.clone(),
                    challenge,
                )
                .unwrap(),
            _ => panic!("Match failed in verify_proof_contribution"),
        }
    }
}

pub fn create_proof(proof_spec: ProofSpec, witness: Witness) -> Proof {
    assert_eq!(
        proof_spec.statements.len(),
        witness.statement_witnesses.len()
    );
    let mut pms: Vec<Box<dyn ProofModule>> = vec![];
    let mut comm_bytes = vec![];
    for (stmt, wit) in proof_spec
        .statements
        .into_iter()
        .zip(witness.statement_witnesses.into_iter())
    {
        match (stmt, wit) {
            (
                /*Statement::PoKSignaturePS( PoKSignaturePS {
                    pk,
                    params,
                    revealed_messages,
                }),*/
                Statement::PoKSignaturePS(s),
                StatementWitness::SignaturePS { sig, messages },
            ) => {
                let mut pm = PSSigProofModule::new(s);
                let mut c =
                    pm.get_hash_contribution(StatementWitness::SignaturePS { sig, messages });
                comm_bytes.append(&mut c);
                pms.push(Box::new(pm))
            }
            (
                /*Statement::PoKSignatureBBS( PoKSignatureBBS {
                    pk,
                    revealed_messages,
                }),*/
                Statement::PoKSignatureBBS(s),
                StatementWitness::SignatureBBS { sig, messages },
            ) => {
                let mut pm = BBSSigProofModule::new(s);
                let mut c =
                    pm.get_hash_contribution(StatementWitness::SignatureBBS { sig, messages });
                comm_bytes.append(&mut c);
                pms.push(Box::new(pm))
            }
            _ => panic!("Match failed in create_proof"),
        }
    }
    let challenge = FieldElement::from_msg_hash(comm_bytes.as_slice());
    let mut statement_proofs: Vec<StatementProof> = vec![];
    for pm in &mut pms {
        let sp = pm.get_proof_contribution(&challenge);
        statement_proofs.push(sp)
    }
    Proof {
        challenge,
        statement_proofs,
    }
}

pub fn verify_proof(proof_spec: ProofSpec, proof: Proof) -> bool {
    assert_eq!(proof_spec.statements.len(), proof.statement_proofs.len());
    let chal = &proof.challenge;
    let mut pms: Vec<Box<dyn ProofModule>> = vec![];
    for (stmt, prf) in proof_spec
        .statements
        .into_iter()
        .zip(proof.statement_proofs.into_iter())
    {
        match (stmt, prf) {
            (Statement::PoKSignaturePS(s), StatementProof::SignaturePSProof(p)) => {
                let pm = PSSigProofModule::new(s);
                let r = pm.verify_proof_contribution(chal, StatementProof::SignaturePSProof(p));
                if !r {
                    return false;
                }
            }
            (Statement::PoKSignatureBBS(s), StatementProof::SignatureBBSProof(p)) => {
                let pm = BBSSigProofModule::new(s);
                let r = pm.verify_proof_contribution(chal, StatementProof::SignatureBBSProof(p));
                if !r {
                    return false;
                }
            }
            _ => panic!(""),
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::field_elem::FieldElementVector;
    use signatures::bbs::keys::generate as BBSKeygen;
    use signatures::ps::keys::keygen as PSKeygen;

    #[test]
    fn test_proof_of_one_ps_sig_from_proof_spec() {
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = PSSig::new(msgs.as_slice(), &sk, &params).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk, &params).unwrap());

        let mut revealed_msgs = HashMap::new();
        revealed_msgs.insert(1, msgs[1].clone());
        revealed_msgs.insert(3, msgs[3].clone());
        revealed_msgs.insert(4, msgs[4].clone());

        let stmt = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: revealed_msgs,
        };
        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt.clone()));

        // Prover's part
        let mut pm_prover = PSSigProofModule::new(stmt.clone());

        let witness = StatementWitness::SignaturePS {
            sig,
            messages: msgs.iter().map(|f| f.clone()).collect(),
        };

        let comm_bytes = pm_prover.get_hash_contribution(witness);
        let chal = FieldElement::from_msg_hash(&comm_bytes);
        let stmt_proof = pm_prover.get_proof_contribution(&chal);

        // Verifier' part
        let pm_verifer = PSSigProofModule::new(stmt);
        pm_verifer.verify_proof_contribution(&chal, stmt_proof);
        /*assert!(PSSigProofModule::verify_proof_contribution(
            &chal,
            proof_spec.statements[0].clone(),
            stmt_proof
        ));*/
    }

    #[test]
    fn test_proof_of_ps_and_bbs_sig() {
        // PS sig
        let count_msgs = 5;
        let msgs_for_PS_sig = FieldElementVector::random(count_msgs);
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        // BBS+ sig
        let message_count = 7;
        let msgs_for_BBS_sig = FieldElementVector::random(message_count);
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        let mut revealed_msgs_for_PS_sig = HashMap::new();
        revealed_msgs_for_PS_sig.insert(1, msgs_for_PS_sig[1].clone());
        revealed_msgs_for_PS_sig.insert(3, msgs_for_PS_sig[3].clone());
        revealed_msgs_for_PS_sig.insert(4, msgs_for_PS_sig[4].clone());

        let mut revealed_msgs_for_BBS_sig = HashMap::new();
        revealed_msgs_for_BBS_sig.insert(1, msgs_for_BBS_sig[1].clone());
        revealed_msgs_for_BBS_sig.insert(2, msgs_for_BBS_sig[2].clone());
        revealed_msgs_for_BBS_sig.insert(6, msgs_for_BBS_sig[6].clone());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: revealed_msgs_for_PS_sig,
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: revealed_msgs_for_BBS_sig,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig.clone()));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig.clone()));

        // Prover's part
        let mut pm_ps_prover = PSSigProofModule::new(stmt_ps_sig.clone());
        let mut pm_bbs_prover = BBSSigProofModule::new(stmt_bbs_sig.clone());

        let witness_PS = StatementWitness::SignaturePS {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        };

        let witness_BBS = StatementWitness::SignatureBBS {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        };

        let mut comm_bytes = vec![];
        comm_bytes.append(&mut pm_ps_prover.get_hash_contribution(witness_PS));
        comm_bytes.append(&mut pm_bbs_prover.get_hash_contribution(witness_BBS));
        let chal = FieldElement::from_msg_hash(&comm_bytes);

        let stmt_ps_proof = pm_ps_prover.get_proof_contribution(&chal);
        let stmt_bbs_proof = pm_bbs_prover.get_proof_contribution(&chal);

        // Verifier' part
        let pm_ps_verifer = PSSigProofModule::new(stmt_ps_sig.clone());
        let pm_bbs_verifer = BBSSigProofModule::new(stmt_bbs_sig.clone());

        assert!(pm_ps_verifer.verify_proof_contribution(
            &chal,
            //            proof_spec.statements[0].clone(),
            stmt_ps_proof
        ));

        assert!(pm_bbs_verifer.verify_proof_contribution(
            &chal,
            //            proof_spec.statements[1].clone(),
            stmt_bbs_proof
        ));
    }

    #[test]
    fn test_proof_of_ps_and_bbs_sig_from_proof_spec() {
        // PS sig
        let count_msgs = 5;
        let msgs_for_PS_sig = FieldElementVector::random(count_msgs);
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        // BBS+ sig
        let message_count = 7;
        let msgs_for_BBS_sig = FieldElementVector::random(message_count);
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        let mut revealed_msgs_for_PS_sig = HashMap::new();
        revealed_msgs_for_PS_sig.insert(1, msgs_for_PS_sig[1].clone());
        revealed_msgs_for_PS_sig.insert(3, msgs_for_PS_sig[3].clone());
        revealed_msgs_for_PS_sig.insert(4, msgs_for_PS_sig[4].clone());

        let mut revealed_msgs_for_BBS_sig = HashMap::new();
        revealed_msgs_for_BBS_sig.insert(1, msgs_for_BBS_sig[1].clone());
        revealed_msgs_for_BBS_sig.insert(2, msgs_for_BBS_sig[2].clone());
        revealed_msgs_for_BBS_sig.insert(6, msgs_for_BBS_sig[6].clone());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: revealed_msgs_for_PS_sig,
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: revealed_msgs_for_BBS_sig,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig.clone()));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig.clone()));

        // Prover's part
        /*let mut pm_ps_prover = PSSigProofModule::new(stmt_ps_sig.clone());
        let mut pm_bbs_prover = BBSSigProofModule::new(stmt_bbs_sig.clone());*/

        let witness_PS = StatementWitness::SignaturePS {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        };

        let witness_BBS = StatementWitness::SignatureBBS {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        };

        let proof = create_proof(
            proof_spec.clone(),
            Witness {
                statement_witnesses: vec![witness_PS, witness_BBS],
            },
        );
        assert!(verify_proof(proof_spec, proof));
        /*let mut comm_bytes = vec![];
        comm_bytes
            .append(&mut pm_ps_prover.get_hash_contribution(witness_PS));
        comm_bytes.append(
            &mut pm_bbs_prover.get_hash_contribution(witness_BBS),
        );*/
        //        let chal = FieldElement::from_msg_hash(&comm_bytes);

        //        let stmt_ps_proof = pm_ps_prover.get_proof_contribution(&chal);

        // Verifier' part
        /*let pm_ps_verifer = PSSigProofModule::new(stmt_ps_sig.clone());
                let pm_bbs_verifer = BBSSigProofModule::new(stmt_bbs_sig.clone());

                assert!(pm_ps_verifer.verify_proof_contribution(
                    &chal,
        //            proof_spec.statements[0].clone(),
                    stmt_ps_proof
                ));

                let stmt_bbs_proof = pm_bbs_prover.get_proof_contribution(&chal);
                assert!(pm_bbs_verifer.verify_proof_contribution(
                    &chal,
        //            proof_spec.statements[1].clone(),
                    stmt_bbs_proof
                ));*/
    }

    #[test]
    fn test_proof_of_two_ps_sigs_from_proof_spec() {}

    #[test]
    fn test_proof_of_equality_of_attr_from_two_ps_sigs_from_proof_spec() {
        // 2 PS sigs, prove an attribute is equal in both
        // TODO: Start passing Blinding factors
    }

    #[test]
    fn test_proof_of_equality_of_attr_from_two_ps_sigs_and_one_bbs_sig_from_proof_spec() {
        // 2 PS, 1 BBS+ sig, prove an attribute is equal in all three
    }

    #[test]
    fn test_proof_of_equality_of_attr_in_2_sigs_when_3_ps_sigs_from_proof_spec() {
        // 3 PS sig, prove an attribute is equal in specific 2 sigs
    }
}
