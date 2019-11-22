use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use failure::_core::ptr::eq;
use signatures::bbs::keys::PublicKey as BBSVerkey;
use signatures::bbs::pok_sig::{PoKOfSignature as PoKBBSSig, PoKOfSignatureProof as PoKBBSigProof};
use signatures::bbs::signature::Signature as BBSSig;
use signatures::ps::keys::{Params as PSParams, Verkey as PSVerkey};
use signatures::ps::pok_sig::{PoKOfSignature as PoKPSSig, PoKOfSignatureProof as PoKPSSigProof};
use signatures::ps::signature::Signature as PSSig;
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

// TODO: Convert panic to error handling

/// MessageRef refers to a message inside an statement. `MessageRef` is used in statements for predicates,
/// like equality, inequality, range, set-membership, non-membership.
#[derive(Clone, Eq)]
pub struct MessageRef {
    pub statement_idx: usize,
    pub message_idx: usize,
}

impl Hash for MessageRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::<u8>::new();
        // TODO: Find an efficient way. The array from `to_be_bytes` should not be cloned
        bytes.extend_from_slice(&self.statement_idx.to_be_bytes());
        bytes.extend_from_slice(":".as_bytes());
        bytes.extend_from_slice(&self.message_idx.to_be_bytes());
        state.write(&bytes);
    }
}

impl PartialEq for MessageRef {
    fn eq(&self, other: &MessageRef) -> bool {
        (self.statement_idx == other.statement_idx) && (self.message_idx == other.message_idx)
    }
}

#[derive(Clone)]
pub enum Statement {
    PoKSignatureBBS(PoKSignatureBBS),
    PoKSignaturePS(PoKSignaturePS),
    Equality(HashSet<MessageRef>),
    // Input validation needed to ensure no conflicts between equality and inequality
    // Inequality(Vec<Ref>),
    // Pedersen commitments are needed during cred request.
    // PedersenCommitment
    SelfAttestedClaim(Vec<u8>),
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

trait PoKSignature {
    fn msg_count(&self) -> usize;
}

impl PoKSignature for PoKSignatureBBS {
    fn msg_count(&self) -> usize {
        self.pk.message_count()
    }
}

impl PoKSignature for PoKSignaturePS {
    fn msg_count(&self) -> usize {
        self.pk.msg_count()
    }
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

#[derive(Clone)]
pub enum StatementWitness {
    SignaturePS(SignaturePSWitness),
    SignatureBBS(SignatureBBSWitness),
}

#[derive(Clone)]
pub struct SignaturePSWitness {
    sig: PSSig,
    messages: Vec<FieldElement>,
    //    blindings: Option<Vec<FieldElement>>
}

#[derive(Clone)]
pub struct SignatureBBSWitness {
    sig: BBSSig,
    messages: Vec<FieldElement>,
    //    blindings: Option<Vec<FieldElement>>
}

#[derive(Clone)]
pub enum StatementProof {
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
    //    pub challenge: FieldElement,
    pub statement_proofs: Vec<StatementProof>,
}

pub trait ProofModule {
    // TODO: Rename
    fn get_hash_contribution(
        &mut self,
        witness: StatementWitness,
        // TODO: Come back to blindings
        //blindings: Vec<FieldElement>,
        // TODO: Accepts errors too
        //) -> Result<Vec<u8>, ZkLangError>;?
    ) -> Vec<u8>;
    fn get_proof_contribution(
        &mut self,
        challenge: &FieldElement,
        // TODO: Accepts errors too
        //) -> Result<StatementProof, ZkLangError>;
    ) -> StatementProof;
    fn verify_proof_contribution(
        &self,
        challenge: &FieldElement,
        proof: StatementProof,
        // TODO: Accepts errors too
        //    ) -> Result<bool, ZkLangError>;
    ) -> bool;
}

pub struct PSSigProofModule {
    pok_sig: Option<PoKPSSig>,
    // TODO: Should this be separated into 2 structs, one for prover, one for verifier?
    pub blindings: Option<Vec<FieldElement>>,
    statement: PoKSignaturePS,
}

impl PSSigProofModule {
    pub fn new(statement: PoKSignaturePS) -> Self {
        Self {
            pok_sig: None,
            blindings: None,
            statement,
        }
    }
}

impl ProofModule for PSSigProofModule {
    fn get_hash_contribution(&mut self, witness: StatementWitness) -> Vec<u8> {
        let pok_sig = match witness {
            StatementWitness::SignaturePS(w) => {
                let indices = (&self.statement)
                    .revealed_messages
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<usize>>();
                /*let blindings = match &w.blindings {
                    Some(b) => Some(b.as_slice()),
                    None => None
                };*/
                let blindings = self.blindings.as_ref().map(|v| v.as_slice());
                PoKPSSig::init(
                    &w.sig,
                    &self.statement.pk,
                    &self.statement.params,
                    &w.messages,
                    blindings,
                    //                    None,
                    indices,
                )
                .unwrap()
            }
            _ => panic!(""),
        };
        let bytes = pok_sig.to_bytes();
        self.pok_sig = Some(pok_sig);
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
    // TODO: Should this be separated into 2 structs, one for prover, one for verifier?
    pub blindings: Option<Vec<FieldElement>>,
    statement: PoKSignatureBBS,
}

impl BBSSigProofModule {
    pub fn new(statement: PoKSignatureBBS) -> Self {
        // Question: Should the statement be stored in ProofModule?
        Self {
            pok_sig: None,
            blindings: None,
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
            StatementWitness::SignatureBBS(w) => {
                let indices = (&self.statement)
                    .revealed_messages
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<usize>>();
                /*let blindings = match &w.blindings {
                  Some(b) => Some(b.as_slice()),
                    None => None
                };*/
                let blindings = self.blindings.as_ref().map(|v| v.as_slice());
                PoKBBSSig::init(
                    &w.sig,
                    &self.statement.pk,
                    &w.messages,
                    blindings,
                    //                    None,
                    indices,
                )
                .unwrap()
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

pub fn create_proof(mut proof_spec: ProofSpec, witness: Witness) -> Proof {
    let mut pms: Vec<Box<dyn ProofModule>> = vec![];
    let mut comm_bytes = vec![];
    // Iterate over statements and check whether refs in equality are valid?
    let mut equalities = Vec::<HashSet<MessageRef>>::new();
    let mut statements = vec![];
    for stmt in proof_spec.statements.iter() {
        statements.push(stmt);
    }
    // TODO: Revealed messages should not be included in equalities.
    // Sidetrack: If a user is not willing to reveal a certain attribute, the verifier can trick
    // him to prove its equality with another attribute that he is revealing.
    // This should be stopped at a higher layer? Or should this code support an option like
    // `never_reveal`?
    build_equalities_for_attributes(&mut equalities, statements);
    // TODO: Build a better data structure where the messages kept per statement such that checking
    // whether a message is present in an equality or not is easier.
    // Choose same blinding for all equal messages
    let blindings_for_equalities = FieldElementVector::random(equalities.len());

    // Remove equality statements since they are already processed
    // Also remove self attested claim statements since they will be processed later
    let mut stmt_indices_to_remove = vec![];
    // Process self attested claims
    let mut self_attest_stmt_bytes = vec![];
    for (i, stmt) in proof_spec.statements.iter_mut().enumerate() {
        match stmt.borrow_mut() {
            Statement::Equality(_) => stmt_indices_to_remove.push(i),
            Statement::SelfAttestedClaim(b) => {
                // Consuming the bytes inside SelfAttestedClaim as the statement is going to be
                // removed after this loop.
                // Question: Is this bad? An alternative would be to clone `b` but `b` can be
                // arbitrarily large.
                self_attest_stmt_bytes.append(b);
                stmt_indices_to_remove.push(i);
            }
            _ => (),
        }
    }
    stmt_indices_to_remove.reverse();
    for i in stmt_indices_to_remove {
        proof_spec.statements.remove(i);
    }

    assert_eq!(
        proof_spec.statements.len(),
        witness.statement_witnesses.len()
    );
    for (stmt_idx, (stmt, wit)) in proof_spec
        .statements
        .into_iter()
        .zip(witness.statement_witnesses.into_iter())
        .enumerate()
    {
        match (stmt, wit) {
            (
                Statement::PoKSignaturePS(s),
                StatementWitness::SignaturePS(SignaturePSWitness { sig, messages }),
            ) => {
                let msg_count = s.msg_count();
                let blindings = generate_blindings_for_statement(
                    stmt_idx,
                    msg_count,
                    &s.revealed_messages,
                    &equalities,
                    &blindings_for_equalities,
                );
                let mut pm = PSSigProofModule::new(s);
                pm.blindings = Some(blindings);
                let mut c =
                    pm.get_hash_contribution(StatementWitness::SignaturePS(SignaturePSWitness {
                        sig,
                        messages,
                    }));
                comm_bytes.append(&mut c);
                pms.push(Box::new(pm))
            }
            (
                Statement::PoKSignatureBBS(s),
                StatementWitness::SignatureBBS(SignatureBBSWitness { sig, messages }),
            ) => {
                let msg_count = s.msg_count();
                let blindings = generate_blindings_for_statement(
                    stmt_idx,
                    msg_count,
                    &s.revealed_messages,
                    &equalities,
                    &blindings_for_equalities,
                );
                let mut pm = BBSSigProofModule::new(s);
                pm.blindings = Some(blindings);
                let mut c =
                    pm.get_hash_contribution(StatementWitness::SignatureBBS(SignatureBBSWitness {
                        sig,
                        messages,
                    }));
                comm_bytes.append(&mut c);
                pms.push(Box::new(pm))
            }
            _ => panic!("Match failed in create_proof"),
        }
    }

    // Append self attested claims to challenge. Same idea as Schnorr signature
    comm_bytes.append(&mut self_attest_stmt_bytes);

    let challenge = FieldElement::from_msg_hash(comm_bytes.as_slice());
    let mut statement_proofs: Vec<StatementProof> = vec![];
    for pm in &mut pms {
        let sp = pm.get_proof_contribution(&challenge);
        statement_proofs.push(sp)
    }
    Proof { statement_proofs }
}

pub fn verify_proof(mut proof_spec: ProofSpec, proof: Proof) -> bool {
    // Iterate over statements and check whether refs in equality are valid?
    let mut equalities = Vec::<HashSet<MessageRef>>::new();
    let mut statements = vec![];
    for stmt in proof_spec.statements.iter() {
        statements.push(stmt);
    }
    build_equalities_for_attributes(&mut equalities, statements);
    // This will hold the response for each equality
    let mut responses_for_equalities: Vec<Option<FieldElement>> = vec![None; equalities.len()];

    // Remove equality statements since they are already processed
    // Also remove self attested claim statements since they will be processed later
    let mut stmt_indices_to_remove = vec![];
    // Process self attested claims
    let mut self_attest_stmt_bytes = vec![];
    for (i, stmt) in proof_spec.statements.iter_mut().enumerate() {
        match stmt.borrow_mut() {
            Statement::Equality(_) => stmt_indices_to_remove.push(i),
            Statement::SelfAttestedClaim(b) => {
                // Consuming the bytes inside SelfAttestedClaim as the statement is going to be
                // removed after this loop.
                // Question: Is this bad? An alternative would be to clone `b` but `b` can be
                // arbitrarily large.
                self_attest_stmt_bytes.append(b);
                stmt_indices_to_remove.push(i);
            }
            _ => (),
        }
    }
    stmt_indices_to_remove.reverse();
    for i in stmt_indices_to_remove {
        proof_spec.statements.remove(i);
    }

    assert_eq!(proof_spec.statements.len(), proof.statement_proofs.len());

    let mut challenge_bytes = vec![];
    for (stmt_idx, (stmt, prf)) in proof_spec
        .statements
        .iter()
        .zip(proof.statement_proofs.iter())
        .enumerate()
    {
        match (stmt, prf) {
            (Statement::PoKSignaturePS(s), StatementProof::SignaturePSProof(p)) => {
                let revealed_msg_indices = s
                    .revealed_messages
                    .keys()
                    .map(|k| *k)
                    .collect::<HashSet<usize>>();

                let msg_count = s.msg_count();
                let r = check_responses_for_equality(
                    stmt_idx,
                    msg_count,
                    &revealed_msg_indices,
                    &equalities,
                    &mut responses_for_equalities,
                    &prf,
                );
                if !r {
                    return false;
                }
                let mut chal_bytes =
                    p.proof
                        .get_bytes_for_challenge(revealed_msg_indices, &s.pk, &s.params);
                challenge_bytes.append(&mut chal_bytes);
            }
            (Statement::PoKSignatureBBS(s), StatementProof::SignatureBBSProof(p)) => {
                let revealed_msg_indices = s
                    .revealed_messages
                    .keys()
                    .map(|k| *k)
                    .collect::<HashSet<usize>>();
                // TODO: Accumulate responses in `responses_for_equalities` and check for equality
                let msg_count = s.msg_count();
                let r = check_responses_for_equality(
                    stmt_idx,
                    msg_count,
                    &revealed_msg_indices,
                    &equalities,
                    &mut responses_for_equalities,
                    &prf,
                );
                if !r {
                    return false;
                }
                let mut chal_bytes = p.proof.get_bytes_for_challenge(revealed_msg_indices, &s.pk);
                challenge_bytes.append(&mut chal_bytes);
            }
            _ => panic!(""),
        }
    }

    // Append self attested claims to challenge. Same idea as Schnorr signature
    challenge_bytes.append(&mut self_attest_stmt_bytes);

    let challenge = FieldElement::from_msg_hash(&challenge_bytes);
    for (stmt, prf) in proof_spec
        .statements
        .into_iter()
        .zip(proof.statement_proofs.into_iter())
    {
        match (stmt, prf) {
            (Statement::PoKSignaturePS(s), StatementProof::SignaturePSProof(p)) => {
                let pm = PSSigProofModule::new(s);
                let r =
                    pm.verify_proof_contribution(&challenge, StatementProof::SignaturePSProof(p));
                if !r {
                    return false;
                }
            }
            (Statement::PoKSignatureBBS(s), StatementProof::SignatureBBSProof(p)) => {
                let pm = BBSSigProofModule::new(s);
                let r =
                    pm.verify_proof_contribution(&challenge, StatementProof::SignatureBBSProof(p));
                if !r {
                    return false;
                }
            }
            _ => panic!(""),
        }
    }
    true
}

// TODO: This should be remove.
fn build_equalities_old(equalities: &mut Vec<HashSet<MessageRef>>, stmt: &Statement) {
    match stmt {
        Statement::Equality(m_refs) => equalities.push(m_refs.clone()),
        _ => (),
    }
    let mut cur_idx = 0;
    while cur_idx < equalities.len() {
        let mut indices_to_merge = vec![];
        for j in cur_idx + 1..equalities.len() {
            if !equalities[cur_idx].is_disjoint(&equalities[j]) {
                indices_to_merge.push(j);
            }
        }
        for i in &indices_to_merge {
            let items: HashSet<MessageRef> = equalities[*i].drain().collect();
            for item in items {
                equalities[cur_idx].insert(item);
            }
        }
        for i in indices_to_merge {
            equalities.remove(i);
        }
        cur_idx += 1;
    }
}

fn build_equalities_for_attributes(
    equalities: &mut Vec<HashSet<MessageRef>>,
    stmts: Vec<&Statement>,
) {
    for stmt in stmts {
        match stmt {
            Statement::Equality(m_refs) => equalities.push(m_refs.clone()),
            _ => (),
        }
    }
    let mut cur_idx = 0;
    while cur_idx < equalities.len() {
        let mut indices_to_merge = vec![];
        // Each set looks for mergeable sets in both directions
        for j in 0..equalities.len() {
            if j == cur_idx {
                continue;
            }
            if !equalities[cur_idx].is_disjoint(&equalities[j]) {
                indices_to_merge.push(j);
            }
        }
        for i in &indices_to_merge {
            let items: HashSet<MessageRef> = equalities[*i].drain().collect();
            for item in items {
                equalities[cur_idx].insert(item);
            }
        }
        // indices_to_merge should be ordered in descending order since removal from array causes
        // size change and removing lower first causes items at higher indices to shift and might
        // invalidate higher indices as well.
        indices_to_merge.sort();
        indices_to_merge.reverse();
        for i in indices_to_merge {
            equalities.remove(i);
        }
        cur_idx += 1;
    }
}

fn generate_blindings_for_statement(
    stmt_idx: usize,
    msg_count: usize,
    revealed_messages: &HashMap<usize, FieldElement>, // TODO: Should be a set and not a map. Don't need values
    equalities: &Vec<HashSet<MessageRef>>,
    blindings_for_equalities: &FieldElementVector,
) -> Vec<FieldElement> {
    let mut blindings = vec![];
    for msg_idx in 0..msg_count {
        if revealed_messages.contains_key(&msg_idx) {
            continue;
        }
        let msg_ref = MessageRef {
            statement_idx: stmt_idx,
            message_idx: msg_idx,
        };
        let mut found = false;
        for i in 0..equalities.len() {
            if equalities[i].contains(&msg_ref) {
                blindings.push(blindings_for_equalities[i].clone());
                found = true;
                break;
            }
        }
        if !found {
            blindings.push(FieldElement::random())
        }
    }
    assert_eq!(blindings.len(), msg_count - revealed_messages.len());
    blindings
}

fn check_responses_for_equality(
    stmt_idx: usize,
    msg_count: usize,
    revealed_msg_indices: &HashSet<usize>,
    equalities: &Vec<HashSet<MessageRef>>,
    responses_for_equalities: &mut Vec<Option<FieldElement>>,
    proof: &StatementProof,
) -> bool {
    for msg_idx in 0..msg_count {
        if revealed_msg_indices.contains(&msg_idx) {
            continue;
        }
        let msg_ref = MessageRef {
            statement_idx: stmt_idx,
            message_idx: msg_idx,
        };
        for i in 0..equalities.len() {
            if equalities[i].contains(&msg_ref) {
                let resp = match proof {
                    StatementProof::SignaturePSProof(p) => {
                        p.proof.get_resp_for_message(msg_idx).unwrap()
                    }
                    StatementProof::SignatureBBSProof(p) => {
                        p.proof.get_resp_for_message(msg_idx).unwrap()
                    }
                    _ => panic!("panic in check_responses_for_equality"),
                };
                if responses_for_equalities[i].is_none() {
                    responses_for_equalities[i] = Some(resp)
                } else {
                    if Some(resp) != responses_for_equalities[i] {
                        return false;
                    }
                }
                break;
            }
        }
    }
    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::field_elem::FieldElementVector;
    use serde_json::error::ErrorCode::Message;
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

        let witness = StatementWitness::SignaturePS(SignaturePSWitness {
            sig,
            messages: msgs.iter().map(|f| f.clone()).collect(),
        });

        let comm_bytes = pm_prover.get_hash_contribution(witness);
        let chal = FieldElement::from_msg_hash(&comm_bytes);
        let stmt_proof = pm_prover.get_proof_contribution(&chal);

        // Verifier' part
        let pm_verifer = PSSigProofModule::new(stmt);
        pm_verifer.verify_proof_contribution(&chal, stmt_proof);
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

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let mut comm_bytes = vec![];
        comm_bytes.append(&mut pm_ps_prover.get_hash_contribution(witness_PS));
        comm_bytes.append(&mut pm_bbs_prover.get_hash_contribution(witness_BBS));
        let chal = FieldElement::from_msg_hash(&comm_bytes);

        let stmt_ps_proof = pm_ps_prover.get_proof_contribution(&chal);
        let stmt_bbs_proof = pm_bbs_prover.get_proof_contribution(&chal);

        // Verifier' part
        let pm_ps_verifer = PSSigProofModule::new(stmt_ps_sig.clone());
        let pm_bbs_verifer = BBSSigProofModule::new(stmt_bbs_sig.clone());

        assert!(pm_ps_verifer.verify_proof_contribution(&chal, stmt_ps_proof));

        assert!(pm_bbs_verifer.verify_proof_contribution(&chal, stmt_bbs_proof));
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

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let proof = create_proof(
            proof_spec.clone(),
            Witness {
                statement_witnesses: vec![witness_PS, witness_BBS],
            },
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof));
    }

    #[test]
    fn test_proof_of_two_ps_sigs_from_proof_spec() {}

    #[test]
    fn test_proof_of_equality_of_attr_from_3_sigs_from_proof_spec() {
        // 3 sigs, PS and BBS+, prove attribute 0 is equal in all 3 signatures,
        // attribute 1 of 1st PS sig is equal to attribute 2 of 2nd PS sig, attribute 2 of 1st PS sig is
        // equal to attribute 3 of BBS+ sig, attribute 4 of 2nd PS sig is equal to attribute 4 of BBS+ sig
        // and attribute 5 and attribute 6 of BBS+ sig are equal
        let params = PSParams::new("test".as_bytes());

        // `common_element` is same in all signatures and is at index 0 in all.
        let common_element = FieldElement::random();

        // PS sig 1
        let count_msgs_1 = 5;
        let mut msgs_for_PS_sig_1 = FieldElementVector::random(count_msgs_1 - 1);
        // attribute 0 is equal in all 3 signatures
        msgs_for_PS_sig_1.insert(0, common_element.clone());
        let (vk_1, sk_1) = PSKeygen(count_msgs_1, &params);
        let ps_sig_1 = PSSig::new(msgs_for_PS_sig_1.as_slice(), &sk_1, &params).unwrap();
        assert!(ps_sig_1
            .verify(msgs_for_PS_sig_1.as_slice(), &vk_1, &params)
            .unwrap());

        // PS sig 2
        let count_msgs_2 = 6;
        let mut msgs_for_PS_sig_2 = FieldElementVector::random(count_msgs_2 - 1);
        // attribute 0 is equal in all 3 signatures
        msgs_for_PS_sig_2.insert(0, common_element.clone());
        // attribute 1 of 1st PS sig is equal to attribute 2 of 2nd PS sig
        msgs_for_PS_sig_2[2] = msgs_for_PS_sig_1[1].clone();
        let (vk_2, sk_2) = PSKeygen(count_msgs_2, &params);
        let ps_sig_2 = PSSig::new(msgs_for_PS_sig_2.as_slice(), &sk_2, &params).unwrap();
        assert!(ps_sig_2
            .verify(msgs_for_PS_sig_2.as_slice(), &vk_2, &params)
            .unwrap());

        // BBS+ sig
        let message_count = 7;
        let mut msgs_for_BBS_sig = FieldElementVector::random(message_count - 1);
        // attribute 0 is equal in all 3 signatures
        msgs_for_BBS_sig.insert(0, common_element.clone());
        // attribute 2 of 1st PS sig is equal to attribute 3 of BBS+ sig
        msgs_for_BBS_sig[3] = msgs_for_PS_sig_1[2].clone();
        // attribute 4 of 2nd PS sig is equal to attribute 4 of BBS+ sig
        msgs_for_BBS_sig[4] = msgs_for_PS_sig_2[4].clone();
        // attribute 5 and attribute 6 of BBS+ sig are equal
        msgs_for_BBS_sig[6] = msgs_for_BBS_sig[5].clone();
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        let stmt_ps_sig_1 = PoKSignaturePS {
            pk: vk_1.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_ps_sig_2 = PoKSignaturePS {
            pk: vk_2.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: HashMap::new(),
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig_1.clone()));
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig_2.clone()));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig.clone()));

        // attribute 0 is equal in all 3 signatures
        let mut eq_1 = HashSet::new();
        eq_1.insert(MessageRef {
            statement_idx: 0,
            message_idx: 0,
        });
        eq_1.insert(MessageRef {
            statement_idx: 1,
            message_idx: 0,
        });
        eq_1.insert(MessageRef {
            statement_idx: 2,
            message_idx: 0,
        });
        proof_spec.add_statement(Statement::Equality(eq_1));

        // attribute 1 of 1st PS sig is equal to attribute 2 of 2nd PS sig
        let mut eq_2 = HashSet::new();
        eq_2.insert(MessageRef {
            statement_idx: 0,
            message_idx: 1,
        });
        eq_2.insert(MessageRef {
            statement_idx: 1,
            message_idx: 2,
        });
        proof_spec.add_statement(Statement::Equality(eq_2));

        // attribute 2 of 1st PS sig is equal to attribute 3 of BBS+ sig
        let mut eq_3 = HashSet::new();
        eq_3.insert(MessageRef {
            statement_idx: 0,
            message_idx: 2,
        });
        eq_3.insert(MessageRef {
            statement_idx: 2,
            message_idx: 3,
        });
        proof_spec.add_statement(Statement::Equality(eq_3));

        // attribute 4 of 2nd PS sig is equal to attribute 4 of BBS+ sig
        let mut eq_4 = HashSet::new();
        eq_4.insert(MessageRef {
            statement_idx: 1,
            message_idx: 4,
        });
        eq_4.insert(MessageRef {
            statement_idx: 2,
            message_idx: 4,
        });
        proof_spec.add_statement(Statement::Equality(eq_4));

        // attribute 5 and attribute 6 of BBS+ sig are equal
        let mut eq_5 = HashSet::new();
        eq_5.insert(MessageRef {
            statement_idx: 2,
            message_idx: 5,
        });
        eq_5.insert(MessageRef {
            statement_idx: 2,
            message_idx: 6,
        });
        proof_spec.add_statement(Statement::Equality(eq_5));

        // Prover's part

        let witness_PS_1 = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig_1,
            messages: msgs_for_PS_sig_1.iter().map(|f| f.clone()).collect(),
        });

        let witness_PS_2 = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig_2,
            messages: msgs_for_PS_sig_2.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let proof = create_proof(
            proof_spec.clone(),
            Witness {
                statement_witnesses: vec![witness_PS_1, witness_PS_2, witness_BBS],
            },
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof));
    }

    #[test]
    fn test_proof_of_equality_of_attr_from_two_ps_sigs_and_one_bbs_sig_from_proof_spec() {
        // 2 PS, 1 BBS+ sig, prove an attribute is equal in all three
    }

    #[test]
    fn test_proof_of_equality_of_attr_in_2_sigs_when_3_ps_sigs_from_proof_spec() {
        // 3 PS sig, prove an attribute is equal in specific 2 sigs
    }

    #[test]
    fn test_self_attested_claims_with_2_PS_sigs() {
        // 2 PS sigs and 3 self attested claims
        let params = PSParams::new("test".as_bytes());

        // 1st PS sig
        let count_msgs_1 = 3;
        let msgs_for_PS_sig_1 = FieldElementVector::random(count_msgs_1);
        let (vk_1, sk_1) = PSKeygen(count_msgs_1, &params);
        let ps_sig_1 = PSSig::new(msgs_for_PS_sig_1.as_slice(), &sk_1, &params).unwrap();
        assert!(ps_sig_1
            .verify(msgs_for_PS_sig_1.as_slice(), &vk_1, &params)
            .unwrap());

        // 2nd PS sig
        let count_msgs_2 = 4;
        let msgs_for_PS_sig_2 = FieldElementVector::random(count_msgs_2);
        let (vk_2, sk_2) = PSKeygen(count_msgs_2, &params);
        let ps_sig_2 = PSSig::new(msgs_for_PS_sig_2.as_slice(), &sk_2, &params).unwrap();
        assert!(ps_sig_2
            .verify(msgs_for_PS_sig_2.as_slice(), &vk_2, &params)
            .unwrap());

        let stmt_ps_sig_1 = PoKSignaturePS {
            pk: vk_1.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_ps_sig_2 = PoKSignaturePS {
            pk: vk_2.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig_1.clone()));

        // 1st self attested claim
        let claim_1 = "My IP is 55.60.72.98";
        proof_spec.add_statement(Statement::SelfAttestedClaim(claim_1.as_bytes().to_vec()));

        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig_2.clone()));

        // 2nd self attested claim
        let claim_2 = "Don't use my proof to buy ammo";
        proof_spec.add_statement(Statement::SelfAttestedClaim(claim_2.as_bytes().to_vec()));

        // 3rd self attested claim
        let claim_3 = "My fav color is black";
        proof_spec.add_statement(Statement::SelfAttestedClaim(claim_3.as_bytes().to_vec()));

        // Prover's part

        let witness_PS_1 = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig_1,
            messages: msgs_for_PS_sig_1.iter().map(|f| f.clone()).collect(),
        });

        let witness_PS_2 = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig_2,
            messages: msgs_for_PS_sig_2.iter().map(|f| f.clone()).collect(),
        });

        let proof = create_proof(
            proof_spec.clone(),
            Witness {
                statement_witnesses: vec![witness_PS_1, witness_PS_2],
            },
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof));
    }

    #[test]
    fn test_build_equalities() {
        let mut equalities = Vec::<HashSet<MessageRef>>::new();
        let mut s1 = HashSet::new();
        s1.insert(MessageRef {
            statement_idx: 0,
            message_idx: 1,
        });
        s1.insert(MessageRef {
            statement_idx: 0,
            message_idx: 4,
        });
        s1.insert(MessageRef {
            statement_idx: 0,
            message_idx: 5,
        });
        let stmt_1 = Statement::Equality(s1);
        build_equalities_old(&mut equalities, &stmt_1);
        assert_eq!(equalities.len(), 1);

        let mut s2 = HashSet::new();
        s2.insert(MessageRef {
            statement_idx: 0,
            message_idx: 5,
        });
        let stmt_2 = Statement::Equality(s2);
        build_equalities_old(&mut equalities, &stmt_2);
        assert_eq!(equalities.len(), 1);

        let mut s3 = HashSet::new();
        s3.insert(MessageRef {
            statement_idx: 1,
            message_idx: 5,
        });
        let stmt_3 = Statement::Equality(s3);
        build_equalities_old(&mut equalities, &stmt_3);
        assert_eq!(equalities.len(), 2);

        let mut s4 = HashSet::new();
        s4.insert(MessageRef {
            statement_idx: 1,
            message_idx: 5,
        });
        s4.insert(MessageRef {
            statement_idx: 2,
            message_idx: 6,
        });
        let stmt_4 = Statement::Equality(s4);
        build_equalities_old(&mut equalities, &stmt_4);
        assert_eq!(equalities.len(), 2);

        // What is a statement like (1, 5) == (0, 4) was added next? Would length change to 1 from 2?
        let mut s5 = HashSet::new();
        s5.insert(MessageRef {
            statement_idx: 1,
            message_idx: 5,
        });
        s5.insert(MessageRef {
            statement_idx: 0,
            message_idx: 4,
        });
        let stmt_5 = Statement::Equality(s5);

        let mut equalities_1 = Vec::<HashSet<MessageRef>>::new();
        let statements = vec![&stmt_1, &stmt_1, &stmt_3, &stmt_4, &stmt_5];
        build_equalities_for_attributes(&mut equalities_1, statements);
        assert_eq!(equalities_1.len(), 1);

        let mut s6 = HashSet::new();
        s6.insert(MessageRef {
            statement_idx: 2,
            message_idx: 7,
        });
        s6.insert(MessageRef {
            statement_idx: 2,
            message_idx: 9,
        });
        let stmt_6 = Statement::Equality(s6);

        let mut equalities_2 = Vec::<HashSet<MessageRef>>::new();
        let statements = vec![&stmt_1, &stmt_1, &stmt_3, &stmt_4, &stmt_5, &stmt_6];
        build_equalities_for_attributes(&mut equalities_2, statements);
        assert_eq!(equalities_2.len(), 2);
    }
}
