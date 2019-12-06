use crate::bulletproofs::r1cs::gadgets::helper_constraints::poseidon::{PoseidonParams, SboxType};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem_g1::G1;
use bulletproofs::r1cs::gadgets::bound_check::{prove_bounded_num, verify_bounded_num};
use bulletproofs::r1cs::gadgets::helper_constraints::sparse_merkle_tree_4_ary::ProofNode_4_ary;
use bulletproofs::r1cs::gadgets::merkle_tree_hash::Arity4MerkleTreeHashConstraints;
use bulletproofs::r1cs::gadgets::set_membership::{prove_set_membership, verify_set_membership};
use bulletproofs::r1cs::gadgets::set_non_membership::{
    prove_set_non_membership, verify_set_non_membership,
};
use bulletproofs::r1cs::gadgets::sparse_merkle_tree_4_ary::{
    prove_leaf_inclusion_4_ary_merkle_tree, verify_leaf_inclusion_4_ary_merkle_tree,
};

use amcl_wrapper::group_elem::GroupElement;
use bulletproofs::r1cs::Generators as BulletproofsGens;
use bulletproofs::r1cs::Prover as BulletproofsProver;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Verifier as BulletproofsVerifier;
use bulletproofs::transcript::TranscriptProtocol;
use merlin::Transcript;
use rand::prelude::ThreadRng;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use signatures::bbs::keys::PublicKey as BBSVerkey;
use signatures::bbs::pok_sig::{PoKOfSignature as PoKBBSSig, PoKOfSignatureProof as PoKBBSigProof};
use signatures::bbs::signature::Signature as BBSSig;
use signatures::ps::keys::{Params as PSParams, Verkey as PSVerkey};
use signatures::ps::pok_sig::{PoKOfSignature as PoKPSSig, PoKOfSignatureProof as PoKPSSigProof};
use signatures::ps::signature::Signature as PSSig;
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

// TODO: Convert panics and asserts to error handling

// Label to be used when seeding the Transcript with commitments from the pre-challenge phase non-bulletproof statements
const TRANSCRIPT_SEEDING_LABEL: &[u8] = "seeding".as_bytes();
// Label to be used when generating the final challenge that will be passed to all sub-protocols
const TRANSCRIPT_FINAL_CHALLENGE_LABEL: &[u8] = "final challenge".as_bytes();

/// MessageRef refers to a message inside an statement. A statement can contain or refer to an array
/// of messages. `MessageRef` is used in statements for predicates,
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

// XXX: Differentiate between statements requiring witness and not requiring witness.
// The latter are usually relying on the former, like statements proving various predicates on
// witnesses of former kind of statements.
// XXX: It might be better to avoid generic type `Arity4MerkleTreeHashConstraints` so that any use
// of statement does not require involving this generic type
#[derive(Clone)]
pub enum Statement<MTHC: Arity4MerkleTreeHashConstraints> {
    //pub enum Statement<'a> {
    PoKSignatureBBS(PoKSignatureBBS),
    PoKSignaturePS(PoKSignaturePS),
    Equality(HashSet<MessageRef>),
    SelfAttestedClaim(Vec<u8>),
    // Range proof over a message from a PS or a BBS sig using Bulletproofs. The range is public.
    RangeProofBulletproof(RangeProofBulletproof),
    SetMemBulletproof(SetMemBulletproof),
    SetNonMemBulletproof(SetNonMemBulletproof),
    Revocation4AryTreeBulletproof(Revocation4AryTreeBulletproof<MTHC>),
    // Input validation needed to ensure no conflicts between equality and inequality
    // Inequality(Vec<Ref>),
    // Pedersen commitments are needed during cred request.
    // PedersenCommitment
}

// Question: The verifier might not care to specify the message values for `revealed_messages`. If
// thats true, change `HashMap<usize, FieldElement>` to `HashMap<usize, Option<FieldElement>>`
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

// Range proof over a message from a PS or a BBS sig. The range is public.
// One approach is, not including Bulletproof generators since and keep only 1 Bulletproof prover/verifier
// per Proof so there will be only 1 set of generators for all statements using Bulletproofs.
// This seems practical but don't know.
#[derive(Clone)]
pub struct RangeProofBulletproof {
    //pub struct RangeProofPSBulletproof<'a> {
    message_ref: MessageRef,
    min: u64,
    max: u64,
    // TODO: Ensure `max_bits_in_val` is appropriate
    max_bits_in_val: usize,
    //gens: &'a BulletproofsGens
}

#[derive(Clone)]
pub struct SetMemBulletproof {
    message_ref: MessageRef,
    set: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct SetNonMemBulletproof {
    message_ref: MessageRef,
    set: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct Revocation4AryTreeBulletproof<MTHC: Arity4MerkleTreeHashConstraints> {
    rev_idx: MessageRef, // Corresponds to the revocation index.
    tree_depth: usize,
    root: FieldElement,
    hash_func: MTHC,
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

/*#[derive(Clone)]
pub struct ProofSpec<'a> {
    pub statements: Vec<Statement<'a>>,
    // TODO: Implement iteration
}*/

#[derive(Clone)]
pub struct ProofSpec<MTHC: Arity4MerkleTreeHashConstraints> {
    pub statements: Vec<Statement<MTHC>>,
    // TODO: Implement iteration
}

#[derive(Clone)]
pub struct Witness {
    pub statement_witnesses: HashMap<usize, StatementWitness>,
    // TODO: Implement iteration
}

#[derive(Clone)]
pub enum StatementWitness {
    SignaturePS(SignaturePSWitness),
    SignatureBBS(SignatureBBSWitness),
    Revocation4AryBP(Revocation4AryBP),
}

#[derive(Clone)]
pub struct SignaturePSWitness {
    sig: PSSig,
    messages: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct SignatureBBSWitness {
    sig: BBSSig,
    messages: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct Revocation4AryBP {
    merkle_proof: Vec<ProofNode_4_ary>,
}

#[derive(Clone)]
pub enum StatementProof {
    SignaturePSProof(SignaturePSProof),
    SignatureBBSProof(SignatureBBSProof),
    BulletproofsProof(BulletproofsProof),
}

#[derive(Clone)]
pub struct SignaturePSProof {
    pub statement_idx: usize,
    pub proof: PoKPSSigProof,
}

#[derive(Clone)]
pub struct SignatureBBSProof {
    pub statement_idx: usize,
    pub proof: PoKBBSigProof,
}

/// For all bulletproof statements, there is a single proof but commitments corresponding to each statement
#[derive(Clone)]
pub struct BulletproofsProof {
    // Map of statement index -> commitments
    pub statement_commitments: HashMap<usize, Vec<G1>>,
    pub proof: R1CSProof,
}

/*impl<'a> ProofSpec<'a> {
    pub fn new() -> Self {
        Self {
            statements: Vec::<Statement>::new(),
        }
    }

    pub fn add_statement(&mut self, statement: Statement<'a>) {
        self.statements.push(statement)
    }
}*/

// TODO: Follow the Builder pattern like ProofSpecBuilder, add_clause, etc
impl<MTHC> ProofSpec<MTHC>
where
    MTHC: Arity4MerkleTreeHashConstraints,
{
    pub fn new() -> Self {
        Self {
            statements: Vec::<Statement<MTHC>>::new(),
        }
    }

    // TODO: Maybe each statement should have an associated unique id which can be a counter
    // so that referencing statements in the proving/verifying code is easy
    pub fn add_statement(&mut self, statement: Statement<MTHC>) {
        // TODO: Input validation: Check that each statement using a reference (with `MessageRef`) has a valid
        // reference, so the statement with index exists and so does the message inside it.
        self.statements.push(statement)
    }

    /// Check if there is any statement for Bulletproofs. Helps is deciding whether to create/load
    /// Bulletproof generators
    // TODO: A better alternative would be to return the number of constraints in all statements
    // combined.
    pub fn has_bulletproof_statements(&self) -> bool {
        for stmt in &self.statements {
            match stmt {
                Statement::RangeProofBulletproof(_) => return true,
                Statement::SetMemBulletproof(_) => return true,
                Statement::SetNonMemBulletproof(_) => return true,
                Statement::Revocation4AryTreeBulletproof(_) => return true,
                _ => (),
            }
        }
        return false;
    }
}

pub struct Proof {
    // Keeping statement_proofs a vector and not a map of statement index -> Proof since several
    // statements can have a single proof, like in case of bulletproofs
    pub statement_proofs: Vec<StatementProof>,
}

pub trait ProofModule {
    // TODO: Rename
    fn get_hash_contribution(
        &mut self,
        witness: StatementWitness,
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

pub struct BBSSigProofModule {
    pok_sig: Option<PoKBBSSig>,
    // TODO: Should this be separated into 2 structs, one for prover, one for verifier?
    pub blindings: Option<Vec<FieldElement>>,
    statement_idx: usize,
    statement: PoKSignatureBBS,
}

impl BBSSigProofModule {
    pub fn new(statement_idx: usize, statement: PoKSignatureBBS) -> Self {
        // Question: Should the statement be stored in ProofModule?
        Self {
            pok_sig: None,
            blindings: None,
            statement_idx,
            statement,
        }
    }
}

pub struct PSSigProofModule {
    pok_sig: Option<PoKPSSig>,
    // TODO: Should this be separated into 2 structs, one for prover, one for verifier?
    pub blindings: Option<Vec<FieldElement>>,
    statement_idx: usize,
    statement: PoKSignaturePS,
}

impl PSSigProofModule {
    pub fn new(statement_idx: usize, statement: PoKSignaturePS) -> Self {
        Self {
            pok_sig: None,
            blindings: None,
            statement_idx,
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
                let blindings = self.blindings.as_ref().map(|v| v.as_slice());
                PoKPSSig::init(
                    &w.sig,
                    &self.statement.pk,
                    &self.statement.params,
                    &w.messages,
                    blindings,
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
        StatementProof::SignaturePSProof(SignaturePSProof {
            statement_idx: self.statement_idx,
            proof,
        })
    }

    fn verify_proof_contribution(&self, challenge: &FieldElement, proof: StatementProof) -> bool {
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

impl ProofModule for BBSSigProofModule {
    fn get_hash_contribution(&mut self, witness: StatementWitness) -> Vec<u8> {
        let pok_sig = match witness {
            StatementWitness::SignatureBBS(w) => {
                let indices = (&self.statement)
                    .revealed_messages
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<usize>>();
                let blindings = self.blindings.as_ref().map(|v| v.as_slice());
                PoKBBSSig::init(&w.sig, &self.statement.pk, &w.messages, blindings, indices)
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
        StatementProof::SignatureBBSProof(SignatureBBSProof {
            statement_idx: self.statement_idx,
            proof,
        })
    }

    fn verify_proof_contribution(&self, challenge: &FieldElement, proof: StatementProof) -> bool {
        match proof {
            StatementProof::SignatureBBSProof(p) => p
                .proof
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

struct RangeProofBPStmt {
    pub min: u64,
    pub max: u64,
    pub max_bits_in_val: usize,
}

struct Revocation4AryBPStmt<MTHC: Arity4MerkleTreeHashConstraints> {
    tree_depth: usize,
    root: FieldElement,
    hash_func: MTHC,
}

// In the following Bulletproof witnesses, the blinding is tracked so that it can be resused in the Schnorr protocol at the end
struct RangeProofBPWitness {
    pub val: u64,
    pub blinding: FieldElement,
}

struct SetMemBPWitness {
    pub val: FieldElement,
    pub blinding: FieldElement,
}

struct SetNonMemBPWitness {
    pub val: FieldElement,
    pub blinding: FieldElement,
}

struct Revocation4AryBPWitness {
    pub leaf_index: FieldElement,
    pub blinding: FieldElement,
}

pub fn create_proof<R: Rng + CryptoRng, MTHC: Clone + Arity4MerkleTreeHashConstraints>(
    mut proof_spec: ProofSpec<MTHC>,
    mut witness: Witness,
    label: &'static [u8],
    bulleproof_gens: Option<&BulletproofsGens>,
) -> Proof {
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

    // References to attributes using part of bulletproofs
    let mut range_proof_bp_refs = HashMap::<MessageRef, usize>::new();
    let mut set_mem_bp_refs = HashMap::<MessageRef, usize>::new();
    let mut set_non_mem_bp_refs = HashMap::<MessageRef, usize>::new();
    let mut revocation_4_ary_refs = HashMap::<MessageRef, usize>::new();

    // Bulletproof statements
    // XXX: What if a Bulletproof statement needed referenced several statement
    // BP statement id -> BP witness
    let mut range_proof_bp_wit = HashMap::new();
    let mut set_mem_bp_wit = HashMap::new();
    let mut set_non_mem_bp_wit = HashMap::new();
    let mut revocation_4_ary_bp_wit = HashMap::new();

    // Vec<(Bulletproof statement index, BP statement, BP witness)>
    let mut range_proof_bp = vec![];
    let mut set_mem_bp = vec![];
    let mut set_non_mem_bp = vec![];
    let mut revocation_4_ary_bp = vec![];

    // Process self attested claims
    let mut self_attest_stmt_bytes = vec![];
    // Indices of Bulletproof statements
    //let mut bp_stmt_indices = HashSet::new();
    for (i, stmt) in proof_spec.statements.iter_mut().enumerate() {
        match stmt.borrow_mut() {
            Statement::SelfAttestedClaim(b) => {
                // Consuming the bytes inside SelfAttestedClaim as the statement is going to be
                // removed after this loop.
                // Question: Is this bad? An alternative would be to clone `b` but `b` can be
                // arbitrarily large.
                self_attest_stmt_bytes.append(b);
            }
            Statement::RangeProofBulletproof(p) => {
                range_proof_bp_refs.insert(p.message_ref.clone(), i);
            }
            Statement::SetMemBulletproof(p) => {
                set_mem_bp_refs.insert(p.message_ref.clone(), i);
            }
            Statement::SetNonMemBulletproof(p) => {
                set_non_mem_bp_refs.insert(p.message_ref.clone(), i);
            }
            Statement::Revocation4AryTreeBulletproof(p) => {
                revocation_4_ary_refs.insert(p.rev_idx.clone(), i);
            }
            _ => (),
        }
    }

    for (stmt_idx, stmt) in proof_spec.statements.into_iter().enumerate() {
        match stmt {
            Statement::PoKSignaturePS(s) => {
                let msg_count = s.msg_count();
                let blindings = generate_blindings_for_statement(
                    stmt_idx,
                    msg_count,
                    &s.revealed_messages,
                    &equalities,
                    &blindings_for_equalities,
                );

                assert!(witness.statement_witnesses.contains_key(&stmt_idx));
                let w = witness.statement_witnesses.remove(&stmt_idx).unwrap();
                match w {
                    StatementWitness::SignaturePS(SignaturePSWitness { sig, messages }) => {
                        prep_bp_blindings_and_values(
                            stmt_idx,
                            &messages,
                            &s.revealed_messages,
                            &blindings,
                            &range_proof_bp_refs,
                            &set_mem_bp_refs,
                            &set_non_mem_bp_refs,
                            &revocation_4_ary_refs,
                            &mut range_proof_bp_wit,
                            &mut set_mem_bp_wit,
                            &mut set_non_mem_bp_wit,
                            &mut revocation_4_ary_bp_wit,
                        );
                        let mut pm = PSSigProofModule::new(stmt_idx, s);
                        pm.blindings = Some(blindings);
                        let mut c = pm.get_hash_contribution(StatementWitness::SignaturePS(
                            SignaturePSWitness { sig, messages },
                        ));
                        comm_bytes.append(&mut c);
                        pms.push(Box::new(pm))
                    }
                    _ => panic!("Witness not for PS"),
                }
            }
            Statement::PoKSignatureBBS(s) => {
                let msg_count = s.msg_count();
                let blindings = generate_blindings_for_statement(
                    stmt_idx,
                    msg_count,
                    &s.revealed_messages,
                    &equalities,
                    &blindings_for_equalities,
                );
                assert!(witness.statement_witnesses.contains_key(&stmt_idx));
                let w = witness.statement_witnesses.remove(&stmt_idx).unwrap();
                match w {
                    StatementWitness::SignatureBBS(SignatureBBSWitness { sig, messages }) => {
                        prep_bp_blindings_and_values(
                            stmt_idx,
                            &messages,
                            &s.revealed_messages,
                            &blindings,
                            &range_proof_bp_refs,
                            &set_mem_bp_refs,
                            &set_non_mem_bp_refs,
                            &revocation_4_ary_refs,
                            &mut range_proof_bp_wit,
                            &mut set_mem_bp_wit,
                            &mut set_non_mem_bp_wit,
                            &mut revocation_4_ary_bp_wit,
                        );
                        let mut pm = BBSSigProofModule::new(stmt_idx, s);
                        pm.blindings = Some(blindings);
                        let mut c = pm.get_hash_contribution(StatementWitness::SignatureBBS(
                            SignatureBBSWitness { sig, messages },
                        ));
                        comm_bytes.append(&mut c);
                        pms.push(Box::new(pm))
                    }
                    _ => panic!("Witness not for BBS+ sig"),
                }
            }
            Statement::RangeProofBulletproof(rp) => {
                range_proof_bp.push((
                    stmt_idx,
                    RangeProofBPStmt {
                        min: rp.min,
                        max: rp.max,
                        max_bits_in_val: rp.max_bits_in_val,
                    },
                    range_proof_bp_wit.remove(&stmt_idx).unwrap(),
                ));
            }
            Statement::SetMemBulletproof(sp) => {
                set_mem_bp.push((stmt_idx, sp.set, set_mem_bp_wit.remove(&stmt_idx).unwrap()));
            }
            Statement::SetNonMemBulletproof(sp) => {
                set_non_mem_bp.push((
                    stmt_idx,
                    sp.set,
                    set_non_mem_bp_wit.remove(&stmt_idx).unwrap(),
                ));
            }
            Statement::Revocation4AryTreeBulletproof(rp) => {
                revocation_4_ary_bp.push((
                    stmt_idx,
                    Revocation4AryBPStmt {
                        tree_depth: rp.tree_depth,
                        root: rp.root,
                        hash_func: rp.hash_func,
                    },
                    revocation_4_ary_bp_wit.remove(&stmt_idx).unwrap(),
                ));
            }
            _ => (),
        }
    }

    // Append self attested claims to challenge. Same idea as Schnorr signature
    comm_bytes.append(&mut self_attest_stmt_bytes);

    // Check if there are any bulletproof statements
    let have_bp_statements = range_proof_bp_refs.len() > 0
        || set_mem_bp_refs.len() > 0
        || set_non_mem_bp_refs.len() > 0
        || revocation_4_ary_refs.len() > 0;

    // TODO: Following if block should initialize a Bulletproofs prover.
    let (challenge, bp_proof) = if have_bp_statements {
        // XXX: Will have just 1 prover for now.
        if bulleproof_gens.is_none() {
            panic!("Need generators for bulletproofs")
        }
        let gens = bulleproof_gens.unwrap();

        let mut transcript = Transcript::new(label);
        transcript.append_message(TRANSCRIPT_SEEDING_LABEL, comm_bytes.as_slice());

        // Using the same blinding in the Bulletproof commitment as in the Schnorr protocol.
        // The choice is arbitrary. It is fine to use different blinding. Same blindings are needed
        // for the Schnorr proof of equality between Bulletproof commitment and the messages under
        // signatures.

        let (statement_commitments, proof) = {
            let mut prover = BulletproofsProver::new(&gens.g, &gens.h, &mut transcript);
            let mut commitments = HashMap::new();
            for (stmt_idx, stmt, wit) in range_proof_bp {
                // TODO: Avoid these clonings
                let comms = prove_bounded_num::<R>(
                    wit.val.clone(),
                    Some(wit.blinding.clone()),
                    stmt.min,
                    stmt.max,
                    stmt.max_bits_in_val,
                    None,
                    &mut prover,
                )
                .unwrap();
                commitments.insert(stmt_idx, comms);
            }

            for (stmt_idx, set, wit) in set_mem_bp {
                // TODO: Avoid these clonings
                let comms = prove_set_membership::<R>(
                    wit.val.clone(),
                    Some(wit.blinding.clone()),
                    &set,
                    None,
                    &mut prover,
                )
                .unwrap();
                commitments.insert(stmt_idx, comms);
            }

            for (stmt_idx, set, wit) in set_non_mem_bp {
                // TODO: Avoid these clonings
                let comms = prove_set_non_membership::<R>(
                    wit.val.clone(),
                    Some(wit.blinding.clone()),
                    &set,
                    None,
                    &mut prover,
                )
                .unwrap();
                commitments.insert(stmt_idx, comms);
            }

            for (stmt_idx, mut stmt, wit) in revocation_4_ary_bp {
                assert!(witness.statement_witnesses.contains_key(&stmt_idx));
                let w = witness.statement_witnesses.remove(&stmt_idx).unwrap();
                match w {
                    StatementWitness::Revocation4AryBP(rp) => {
                        let comms = prove_leaf_inclusion_4_ary_merkle_tree::<R, MTHC>(
                            FieldElement::one(),
                            wit.leaf_index.clone(),
                            false,
                            Some(vec![wit.blinding.clone()]),
                            rp.merkle_proof,
                            &stmt.root,
                            stmt.tree_depth,
                            &mut stmt.hash_func,
                            None,
                            &mut prover,
                        )
                        .unwrap();
                        commitments.insert(stmt_idx, comms);
                    }
                    _ => panic!("Not a revocation witness"),
                };
            }

            let proof = prover.prove(&gens.G, &gens.H).unwrap();
            (commitments, proof)
        };
        (
            transcript.challenge_scalar(TRANSCRIPT_FINAL_CHALLENGE_LABEL),
            Some(BulletproofsProof {
                statement_commitments,
                proof,
            }),
        )
    } else {
        (FieldElement::from_msg_hash(comm_bytes.as_slice()), None)
    };

    let mut statement_proofs: Vec<StatementProof> = vec![];
    for pm in &mut pms {
        let sp = pm.get_proof_contribution(&challenge);
        statement_proofs.push(sp)
    }

    if bp_proof.is_some() {
        // TODO: Prove that bulletproof commits to same values
        statement_proofs.push(StatementProof::BulletproofsProof(bp_proof.unwrap()));
    }

    Proof { statement_proofs }
}

pub fn verify_proof<MTHC: Clone + Arity4MerkleTreeHashConstraints>(
    mut proof_spec: ProofSpec<MTHC>,
    mut proof: Proof,
    label: &'static [u8],
    bulleproof_gens: Option<&BulletproofsGens>,
) -> bool {
    // Iterate over statements and check whether refs in equality are valid?
    let mut equalities = Vec::<HashSet<MessageRef>>::new();
    let mut statements = vec![];
    for stmt in proof_spec.statements.iter() {
        statements.push(stmt);
    }
    build_equalities_for_attributes(&mut equalities, statements);
    // This will hold the response for each equality
    let mut responses_for_equalities: Vec<Option<FieldElement>> = vec![None; equalities.len()];

    // Process self attested claims
    let mut self_attest_stmt_bytes = vec![];
    for (i, stmt) in proof_spec.statements.iter_mut().enumerate() {
        match stmt.borrow_mut() {
            Statement::SelfAttestedClaim(b) => {
                // Consuming the bytes inside SelfAttestedClaim as the statement is going to be
                // removed after this loop.
                // Question: Is this bad? An alternative would be to clone `b` but `b` can be
                // arbitrarily large.
                self_attest_stmt_bytes.append(b);
            }
            _ => (),
        }
    }

    let mut challenge_bytes = vec![];

    let mut range_proof_bp = vec![];
    let mut set_mem_bp = vec![];
    let mut set_non_mem_bp = vec![];
    let mut revocation_4_ary_bp = vec![];

    for (stmt_idx, stmt) in proof_spec.statements.iter().enumerate() {
        match stmt {
            Statement::PoKSignaturePS(s) => {
                let revealed_msg_indices = s
                    .revealed_messages
                    .keys()
                    .map(|k| *k)
                    .collect::<HashSet<usize>>();

                let msg_count = s.msg_count();
                // TODO: Make a macro to reuse code.
                let mut found = false;
                for p in &proof.statement_proofs {
                    match p {
                        StatementProof::SignaturePSProof(prf) => {
                            if prf.statement_idx == stmt_idx {
                                let r = check_responses_for_equality(
                                    stmt_idx,
                                    msg_count,
                                    &revealed_msg_indices,
                                    &equalities,
                                    &mut responses_for_equalities,
                                    &p,
                                );
                                if !r {
                                    return false;
                                }

                                let mut chal_bytes = prf.proof.get_bytes_for_challenge(
                                    revealed_msg_indices,
                                    &s.pk,
                                    &s.params,
                                );
                                challenge_bytes.append(&mut chal_bytes);
                                found = true;
                                break;
                            }
                        }
                        _ => (),
                    }
                }
                if !found {
                    panic!("Proof not found for statement {}", stmt_idx)
                }
            }
            Statement::PoKSignatureBBS(s) => {
                let revealed_msg_indices = s
                    .revealed_messages
                    .keys()
                    .map(|k| *k)
                    .collect::<HashSet<usize>>();
                // TODO: Accumulate responses in `responses_for_equalities` and check for equality
                let msg_count = s.msg_count();
                // TODO: Make a macro to reuse code.
                let mut found = false;
                for p in &proof.statement_proofs {
                    match p {
                        StatementProof::SignatureBBSProof(prf) => {
                            if prf.statement_idx == stmt_idx {
                                let r = check_responses_for_equality(
                                    stmt_idx,
                                    msg_count,
                                    &revealed_msg_indices,
                                    &equalities,
                                    &mut responses_for_equalities,
                                    &p,
                                );
                                if !r {
                                    return false;
                                }
                                let mut chal_bytes = prf
                                    .proof
                                    .get_bytes_for_challenge(revealed_msg_indices, &s.pk);
                                challenge_bytes.append(&mut chal_bytes);
                                found = true;
                                break;
                            }
                        }
                        _ => (),
                    }
                }
                if !found {
                    panic!("Proof not found for statement {}", stmt_idx)
                }
            }
            Statement::RangeProofBulletproof(rp) => {
                range_proof_bp.push((
                    stmt_idx,
                    RangeProofBPStmt {
                        min: rp.min,
                        max: rp.max,
                        max_bits_in_val: rp.max_bits_in_val,
                    },
                ));
            }
            Statement::SetMemBulletproof(sp) => {
                set_mem_bp.push((stmt_idx, sp.set.clone()));
            }
            Statement::SetNonMemBulletproof(sp) => {
                set_non_mem_bp.push((stmt_idx, sp.set.clone()));
            }
            Statement::Revocation4AryTreeBulletproof(rp) => {
                revocation_4_ary_bp.push((
                    stmt_idx,
                    Revocation4AryBPStmt {
                        tree_depth: rp.tree_depth,
                        root: rp.root.clone(),
                        hash_func: rp.hash_func.clone(),
                    },
                ));
            }
            _ => (),
        }
    }

    // Append self attested claims to challenge. Same idea as Schnorr signature
    challenge_bytes.append(&mut self_attest_stmt_bytes);

    // Check if there are any bulletproof statements
    let have_bp_statements = range_proof_bp.len() > 0
        || set_mem_bp.len() > 0
        || set_non_mem_bp.len() > 0
        || revocation_4_ary_bp.len() > 0;

    let challenge = if have_bp_statements {
        // XXX: Will have just 1 verifier for now.
        if bulleproof_gens.is_none() {
            panic!("Need generators for bulletproofs")
        }
        let gens = bulleproof_gens.unwrap();

        let mut transcript = Transcript::new(label);
        transcript.append_message(TRANSCRIPT_SEEDING_LABEL, challenge_bytes.as_slice());
        let mut verifier = BulletproofsVerifier::new(&mut transcript);
        let mut bp_proof: Option<&mut BulletproofsProof> = None;
        for p in proof.statement_proofs.iter_mut() {
            match p {
                StatementProof::BulletproofsProof(prf) => {
                    bp_proof = Some(prf);
                    break;
                }
                _ => (),
            }
        }
        if bp_proof.is_none() {
            panic!("BulletproofsProof not found in statement proofs")
        }
        let bp_proof = bp_proof.unwrap();

        // TODO: Verify that bulletproof commits to same values

        for (stmt_idx, stmt) in range_proof_bp {
            let comms = bp_proof.statement_commitments.remove(&stmt_idx);
            // TODO: use `ok_or` on the option
            if comms.is_none() {
                panic!(
                    "BulletproofsProof commitments not found in for statement index {}",
                    stmt_idx
                );
            }
            let comms = comms.unwrap();
            verify_bounded_num(
                stmt.min,
                stmt.max,
                stmt.max_bits_in_val,
                comms,
                &mut verifier,
            )
            .unwrap();
        }

        for (stmt_idx, set) in set_mem_bp {
            let comms = bp_proof.statement_commitments.remove(&stmt_idx);
            // TODO: use `ok_or` on the option
            if comms.is_none() {
                panic!(
                    "BulletproofsProof commitments not found in for statement index {}",
                    stmt_idx
                );
            }
            let comms = comms.unwrap();
            verify_set_membership(&set, comms, &mut verifier).unwrap();
        }

        for (stmt_idx, set) in set_non_mem_bp {
            let comms = bp_proof.statement_commitments.remove(&stmt_idx);
            // TODO: use `ok_or` on the option
            if comms.is_none() {
                panic!(
                    "BulletproofsProof commitments not found in for statement index {}",
                    stmt_idx
                );
            }
            let comms = comms.unwrap();
            verify_set_non_membership(&set, comms, &mut verifier).unwrap();
        }

        for (stmt_idx, mut stmt) in revocation_4_ary_bp {
            let comms = bp_proof.statement_commitments.remove(&stmt_idx);
            // TODO: use `ok_or` on the option
            if comms.is_none() {
                panic!(
                    "BulletproofsProof commitments not found in for statement index {}",
                    stmt_idx
                );
            }
            let comms = comms.unwrap();
            verify_leaf_inclusion_4_ary_merkle_tree::<MTHC>(
                &stmt.root,
                stmt.tree_depth,
                &mut stmt.hash_func,
                Some(FieldElement::one()),
                comms,
                &gens.g,
                &gens.h,
                &mut verifier,
            )
            .unwrap();
        }

        verifier
            .verify(&bp_proof.proof, &gens.g, &gens.h, &gens.G, &gens.H)
            .unwrap();
        transcript.challenge_scalar(TRANSCRIPT_FINAL_CHALLENGE_LABEL)
    } else {
        FieldElement::from_msg_hash(&challenge_bytes)
    };

    for (stmt_idx, stmt) in proof_spec.statements.into_iter().enumerate() {
        match stmt {
            Statement::PoKSignaturePS(s) => {
                let pm = PSSigProofModule::new(stmt_idx, s);
                // TODO: Make a macro to reuse code.
                let mut prf_idx = None;
                for (i, p) in proof.statement_proofs.iter().enumerate() {
                    match p {
                        StatementProof::SignaturePSProof(prf) => {
                            if prf.statement_idx == stmt_idx {
                                prf_idx = Some(i);
                                break;
                            }
                        }
                        _ => (),
                    }
                }
                if prf_idx.is_none() {
                    panic!("Statement proof not found for index {}", stmt_idx);
                }
                let p = proof.statement_proofs.remove(prf_idx.unwrap());
                let r = pm.verify_proof_contribution(&challenge, p);
                if !r {
                    return false;
                }
            }
            Statement::PoKSignatureBBS(s) => {
                let pm = BBSSigProofModule::new(stmt_idx, s);
                // TODO: Make a macro to reuse code.
                let mut prf_idx = None;
                for (i, p) in proof.statement_proofs.iter().enumerate() {
                    match p {
                        StatementProof::SignatureBBSProof(prf) => {
                            if prf.statement_idx == stmt_idx {
                                prf_idx = Some(i);
                                break;
                            }
                        }
                        _ => (),
                    }
                }
                if prf_idx.is_none() {
                    panic!("Statement proof not found for index {}", stmt_idx);
                }
                let p = proof.statement_proofs.remove(prf_idx.unwrap());
                let r = pm.verify_proof_contribution(&challenge, p);
                if !r {
                    return false;
                }
            }
            _ => (),
        }
    }
    true
}

/// Prepare blindings and for various bulletproof statements
fn prep_bp_blindings_and_values(
    stmt_idx: usize,
    messages: &[FieldElement],
    revealed_messages: &HashMap<usize, FieldElement>,
    blindings: &[FieldElement],
    range_proof_bp_refs: &HashMap<MessageRef, usize>,
    set_mem_bp_refs: &HashMap<MessageRef, usize>,
    set_non_mem_bp_refs: &HashMap<MessageRef, usize>,
    revocation_4_ary_refs: &HashMap<MessageRef, usize>,
    range_proof_bp_wit: &mut HashMap<usize, RangeProofBPWitness>,
    set_mem_bp_wit: &mut HashMap<usize, SetMemBPWitness>,
    set_non_mem_bp_wit: &mut HashMap<usize, SetNonMemBPWitness>,
    revocation_4_ary_bp_wit: &mut HashMap<usize, Revocation4AryBPWitness>,
) {
    for i in 0..messages.len() {
        if revealed_messages.contains_key(&i) {
            continue;
        }
        let msg_ref = MessageRef {
            statement_idx: stmt_idx,
            message_idx: i,
        };
        if range_proof_bp_refs.contains_key(&msg_ref) {
            // TODO: Add a to_u64 in FieldElement
            let val = messages[i].to_bignum().w[0] as u64;
            range_proof_bp_wit.insert(
                range_proof_bp_refs[&msg_ref],
                RangeProofBPWitness {
                    val,
                    blinding: blindings[i].clone(),
                },
            );
        } else if set_mem_bp_refs.contains_key(&msg_ref) {
            set_mem_bp_wit.insert(
                set_mem_bp_refs[&msg_ref],
                SetMemBPWitness {
                    val: messages[i].clone(),
                    blinding: blindings[i].clone(),
                },
            );
        } else if set_non_mem_bp_refs.contains_key(&msg_ref) {
            set_non_mem_bp_wit.insert(
                set_non_mem_bp_refs[&msg_ref],
                SetNonMemBPWitness {
                    val: messages[i].clone(),
                    blinding: blindings[i].clone(),
                },
            );
        } else if revocation_4_ary_refs.contains_key(&msg_ref) {
            revocation_4_ary_bp_wit.insert(
                revocation_4_ary_refs[&msg_ref],
                Revocation4AryBPWitness {
                    leaf_index: messages[i].clone(),
                    blinding: blindings[i].clone(),
                },
            );
        }
    }
}

/// Merge equalities of various statements such that the final array of equality sets are disjoint.
/// Given Vec[ Set[(0, 1), (1, 3)], Set[(1, 3), (2, 4)], Set[(4, 5), (2, 6)] ] = Vec[ Set[(0, 1), (1, 3), (2, 4)], Set[(4, 5), (2, 6)] ]
fn build_equalities_for_attributes<MTHC: Arity4MerkleTreeHashConstraints>(
    equalities: &mut Vec<HashSet<MessageRef>>,
    stmts: Vec<&Statement<MTHC>>,
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

// Generate blindings for messages in a statement. It ensures that messages that need to be proved
// equal have same blindings
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
    use crate::bulletproofs::r1cs::gadgets::helper_constraints::poseidon::CAP_CONST_W_5;
    use crate::bulletproofs::r1cs::gadgets::helper_constraints::sparse_merkle_tree_4_ary::{
        DBVal_4_ary, VanillaSparseMerkleTree_4,
    };
    use crate::bulletproofs::r1cs::gadgets::merkle_tree_hash::{
        PoseidonHashConstraints, PoseidonHash_4,
    };
    use crate::bulletproofs::utils::hash_db::InMemoryHashDb;
    use amcl_wrapper::field_elem::FieldElementVector;
    use failure::_core::cmp::min;
    use rand::rngs::OsRng;
    use rand::Rng;
    use serde_json::error::ErrorCode::Message;
    use signatures::bbs::keys::generate as BBSKeygen;
    use signatures::ps::keys::keygen as PSKeygen;
    use std::thread::Thread;

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

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);
        statement_witnesses.insert(1, witness_BBS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };
        // TODO: Is this the right way to do things
        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
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
        proof_spec.add_statement(Statement::Equality::<PoseidonHashConstraints>(eq_1));

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
        proof_spec.add_statement(Statement::Equality::<PoseidonHashConstraints>(eq_2));

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
        proof_spec.add_statement(Statement::Equality::<PoseidonHashConstraints>(eq_3));

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
        proof_spec.add_statement(Statement::Equality::<PoseidonHashConstraints>(eq_4));

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
        proof_spec.add_statement(Statement::Equality::<PoseidonHashConstraints>(eq_5));

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

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS_1);
        statement_witnesses.insert(1, witness_PS_2);
        statement_witnesses.insert(2, witness_BBS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
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

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS_1);
        statement_witnesses.insert(2, witness_PS_2);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_sig_and_range_proof_over_1_message() {
        // Prove knowledge of a PS signature and prove that one of the attribute is in a given range
        let min = 5;
        let max = 25;
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);
        let min = 5;
        let max = 25;
        // This message will be proved in [min, max]
        msgs_for_PS_sig[2] = FieldElement::from(10u64);
        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        // For statement index 0, message index 2 is in [min, max]
        let stmt_range_proof = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 2,
            },
            min,
            max,
            max_bits_in_val: 64,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });
        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_and_bbs_sig_and_range_proof_over_several_messages() {
        // Prove knowledge of a PS and a BBS+ signature and certain attributes are in a given range
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);

        let min_1 = 100;
        let max_1 = 200;
        // This message will be proved in [min_1, max_1]
        msgs_for_PS_sig[1] = FieldElement::from(192u64);

        let min_2 = 29;
        let max_2 = 35;
        // This message will be proved in [min_2, max_2]
        msgs_for_PS_sig[4] = FieldElement::from(31u64);

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        // BBS+ sig
        let message_count = 7;
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let mut msgs_for_BBS_sig = FieldElementVector::random(message_count);

        let min_3 = 100000000;
        let max_3 = 200000000000;
        // This message will be proved in [min_3, max_3]
        msgs_for_BBS_sig[1] = FieldElement::from(100000002u64);

        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: HashMap::new(),
        };

        // For statement index 0, message index 1 is in [min_1, max_1]
        let stmt_range_proof_1 = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 1,
            },
            min: min_1,
            max: max_1,
            max_bits_in_val: 64,
        };

        // For statement index 0, message index 4 is in [min_2, max_2]
        let stmt_range_proof_2 = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 4,
            },
            min: min_2,
            max: max_2,
            max_bits_in_val: 64,
        };

        // For statement index 1, message index 1 is in [min_3, max_3]
        let stmt_range_proof_3 = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 1,
                message_idx: 1,
            },
            min: min_3,
            max: max_3,
            max_bits_in_val: 64,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof_1));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof_2));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof_3));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);
        statement_witnesses.insert(1, witness_BBS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_sig_and_set_membership_over_1_message() {
        // Prove knowledge of a PS signature and prove that one of the attribute is member of a given set
        let min = 5;
        let max = 25;
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);

        let set = (0..10).map(|_| FieldElement::random()).collect::<Vec<_>>();
        // This message will be used in set membership test
        msgs_for_PS_sig[2] = set[5].clone();

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        // For statement index 0, message index 2 is member of set `set`
        let stmt_set_mem = SetMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 2,
            },
            set,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::SetMemBulletproof(stmt_set_mem));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });
        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_sig_and_set_non_membership_over_1_message() {
        // Prove knowledge of a PS signature and prove that one of the attribute is not a member of a given set
        let min = 5;
        let max = 25;
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let msgs_for_PS_sig = FieldElementVector::random(count_msgs);

        // Randomly chosen set elements so rare chance of collision with `msgs_for_PS_sig`
        let set = (0..10).map(|_| FieldElement::random()).collect::<Vec<_>>();

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        // For statement index 0, message index 2 is not a member of set `set`
        let stmt_set_non_mem = SetNonMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 2,
            },
            set,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::SetNonMemBulletproof(stmt_set_non_mem));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });
        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_and_bbs_sig_and_various_bulletproof_statements() {
        // Prove knowledge of a PS and a BBS+ signature and certain attribute is in a given range,
        // certain attribute is a member of a set and certain attribute is not a member of a set

        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);

        let min_1 = 100;
        let max_1 = 200;
        // This message will be proved in [min_1, max_1]
        msgs_for_PS_sig[1] = FieldElement::from(192u64);

        let set_1 = (0..10).map(|_| FieldElement::random()).collect::<Vec<_>>();
        // This message will be used in set membership test
        msgs_for_PS_sig[3] = set_1[5].clone();

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        // BBS+ sig
        let message_count = 7;
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let mut msgs_for_BBS_sig = FieldElementVector::random(message_count);

        let min_2 = 100000000;
        let max_2 = 200000000000;
        // This message will be proved in [min_3, max_3]
        msgs_for_BBS_sig[2] = FieldElement::from(100000002u64);

        let set_2 = (0..10).map(|_| FieldElement::random()).collect::<Vec<_>>();
        // This message will be used in set membership test
        msgs_for_BBS_sig[4] = set_1[8].clone();
        msgs_for_BBS_sig[5] = set_2[2].clone();

        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: HashMap::new(),
        };

        // For statement index 0, message index 1 is in [min_1, max_1]
        let stmt_range_proof_1 = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 1,
            },
            min: min_1,
            max: max_1,
            max_bits_in_val: 64,
        };

        // For statement index 1, message index 2 is in [min_2, max_2]
        let stmt_range_proof_2 = RangeProofBulletproof {
            message_ref: MessageRef {
                statement_idx: 1,
                message_idx: 2,
            },
            min: min_2,
            max: max_2,
            max_bits_in_val: 64,
        };

        // For statement index 0, message index 3 is member of set `set_1`
        let stmt_set_mem_1 = SetMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 3,
            },
            set: set_1.clone(),
        };

        // For statement index 1, message index 4 is member of set `set_1`
        let stmt_set_mem_2 = SetMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 1,
                message_idx: 4,
            },
            set: set_1.clone(),
        };

        // For statement index 1, message index 5 is member of set `set_2`
        let stmt_set_mem_3 = SetMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 1,
                message_idx: 5,
            },
            set: set_2.clone(),
        };

        // For statement index 0, message index 0 is not a member of set `set_1`
        let stmt_set_non_mem_1 = SetNonMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 0,
                message_idx: 0,
            },
            set: set_1,
        };

        // For statement index 1, message index 0 is not a member of set `set_2`
        let stmt_set_non_mem_2 = SetNonMemBulletproof {
            message_ref: MessageRef {
                statement_idx: 1,
                message_idx: 0,
            },
            set: set_2,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof_1));
        proof_spec.add_statement(Statement::RangeProofBulletproof(stmt_range_proof_2));
        proof_spec.add_statement(Statement::SetMemBulletproof(stmt_set_mem_1));
        proof_spec.add_statement(Statement::SetMemBulletproof(stmt_set_mem_2));
        proof_spec.add_statement(Statement::SetMemBulletproof(stmt_set_mem_3));
        proof_spec.add_statement(Statement::SetNonMemBulletproof(stmt_set_non_mem_1));
        proof_spec.add_statement(Statement::SetNonMemBulletproof(stmt_set_non_mem_2));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);
        statement_witnesses.insert(1, witness_BBS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 512);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    // Create and update a tree and return the merkle proof and hash constraints
    fn setup_for_revocation(
        tree_depth: usize,
        prover_leaf_index: &FieldElement,
    ) -> (FieldElement, Vec<ProofNode_4_ary>, PoseidonParams) {
        let mut db = InMemoryHashDb::<DBVal_4_ary>::new();
        let width = 5;
        let (full_b, full_e, partial_rounds) = (4, 4, 56);
        let total_rounds = full_b + partial_rounds + full_e;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();
        let sbox = &SboxType::Quint;
        let hash_func = PoseidonHash_4 {
            params: &hash_params,
            sbox,
        };

        let mut tree = VanillaSparseMerkleTree_4::new(&hash_func, tree_depth, &mut db).unwrap();

        // Assign 10 leaves to 1, 0 means revoked, prover will prove non revoked
        for i in 1..=10 {
            let rev_index = FieldElement::from(i as u32);
            tree.update(&rev_index, FieldElement::one(), &mut db)
                .unwrap();
        }

        let mut merkle_proof_vec = Vec::<ProofNode_4_ary>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        // Non revoked indices will have value as 1.
        let leaf_value = FieldElement::one();

        assert_eq!(
            leaf_value,
            tree.get(prover_leaf_index, &mut merkle_proof, &db).unwrap()
        );
        merkle_proof_vec = merkle_proof.unwrap();
        assert!(tree
            .verify_proof(
                prover_leaf_index,
                &leaf_value,
                &merkle_proof_vec,
                Some(&tree.root)
            )
            .unwrap());
        (tree.root, merkle_proof_vec, hash_params)
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_sig_and_recovation_4_ary_with_bulletproof() {
        // Prove knowledge of PS sig and being non revoked
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);
        // prover's leaf index is 5
        let prover_leaf_index = FieldElement::from(5);
        // Index 1 is reserved for revocation. This choice is arbitrary.
        msgs_for_PS_sig[1] = prover_leaf_index.clone();

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        // Create and update tree. This part will be done by the issuer. The issuer might host the
        // tree himself or on a ledger
        let tree_depth = 2; // 16 leaves, for testing
        let (tree_root, merkle_proof_vec, hash_params) =
            setup_for_revocation(tree_depth, &prover_leaf_index);
        let sbox = &SboxType::Quint;
        let mut hash_func_constraints =
            PoseidonHashConstraints::new(&hash_params, sbox, CAP_CONST_W_5);

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_revok_bp = Revocation4AryTreeBulletproof {
            rev_idx: MessageRef {
                statement_idx: 0,
                message_idx: 1,
            },
            tree_depth,
            root: tree_root.clone(),
            hash_func: hash_func_constraints,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::Revocation4AryTreeBulletproof(stmt_revok_bp));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_revocation = StatementWitness::Revocation4AryBP(Revocation4AryBP {
            merkle_proof: merkle_proof_vec,
        });
        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);
        statement_witnesses.insert(1, witness_revocation);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 1024);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
    }

    #[test]
    fn test_proof_of_knowledge_of_ps_and_bbs_sig_and_recovation_4_ary_with_bulletproof() {
        // Prove knowledge of a PS sig and a BBS sig and both of them being non revoked
        // PS sig
        let count_msgs = 5;
        let params = PSParams::new("test".as_bytes());
        let (vk, sk) = PSKeygen(count_msgs, &params);
        let mut msgs_for_PS_sig = FieldElementVector::random(count_msgs);
        // prover's leaf index is 5 in the PS signature
        let prover_leaf_index_PS = FieldElement::from(5);
        // Index 1 is reserved for revocation in this signature. This choice is arbitrary.
        msgs_for_PS_sig[1] = prover_leaf_index_PS.clone();

        let ps_sig = PSSig::new(msgs_for_PS_sig.as_slice(), &sk, &params).unwrap();
        assert!(ps_sig
            .verify(msgs_for_PS_sig.as_slice(), &vk, &params)
            .unwrap());

        let sbox = &SboxType::Quint;

        // Revocation tree for PS sig's issuer.
        let tree_depth_PS = 2; // 16 leaves, for testing
        let (tree_root_PS, merkle_proof_vec_PS, hash_params_PS) =
            setup_for_revocation(tree_depth_PS, &prover_leaf_index_PS);
        let mut hash_func_constraints_PS =
            PoseidonHashConstraints::new(&hash_params_PS, sbox, CAP_CONST_W_5);

        // BBS+ sig
        let message_count = 7;
        let (verkey, signkey) = BBSKeygen(message_count).unwrap();
        let mut msgs_for_BBS_sig = FieldElementVector::random(message_count);
        // prover's leaf index is 6 in the BBS+ signature
        let prover_leaf_index_BBS = FieldElement::from(6);
        // Index 2 is reserved for revocation in this signature. This choice is arbitrary.
        msgs_for_BBS_sig[2] = prover_leaf_index_BBS.clone();
        let bbs_sig = BBSSig::new(msgs_for_BBS_sig.as_slice(), &signkey, &verkey).unwrap();
        assert!(bbs_sig
            .verify(msgs_for_BBS_sig.as_slice(), &verkey)
            .unwrap());

        // Revocation tree for BBS+ sig's issuer.
        let tree_depth_BBS = 3; // 64 leaves, for testing
        let (tree_root_BBS, merkle_proof_vec_BBS, hash_params_BBS) =
            setup_for_revocation(tree_depth_BBS, &prover_leaf_index_BBS);
        let mut hash_func_constraints_BBS =
            PoseidonHashConstraints::new(&hash_params_BBS, sbox, CAP_CONST_W_5);

        let stmt_ps_sig = PoKSignaturePS {
            pk: vk.clone(),
            params: params.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_bbs_sig = PoKSignatureBBS {
            pk: verkey.clone(),
            revealed_messages: HashMap::new(),
        };

        let stmt_revok_bp_PS = Revocation4AryTreeBulletproof {
            rev_idx: MessageRef {
                statement_idx: 0,
                message_idx: 1,
            },
            tree_depth: tree_depth_PS,
            root: tree_root_PS.clone(),
            hash_func: hash_func_constraints_PS,
        };

        let stmt_revok_bp_BBS = Revocation4AryTreeBulletproof {
            rev_idx: MessageRef {
                statement_idx: 1,
                message_idx: 2,
            },
            tree_depth: tree_depth_BBS,
            root: tree_root_BBS.clone(),
            hash_func: hash_func_constraints_BBS,
        };

        let mut proof_spec = ProofSpec::new();
        proof_spec.add_statement(Statement::PoKSignaturePS(stmt_ps_sig));
        proof_spec.add_statement(Statement::PoKSignatureBBS(stmt_bbs_sig));
        proof_spec.add_statement(Statement::Revocation4AryTreeBulletproof(stmt_revok_bp_PS));
        proof_spec.add_statement(Statement::Revocation4AryTreeBulletproof(stmt_revok_bp_BBS));

        // Prover's part

        let witness_PS = StatementWitness::SignaturePS(SignaturePSWitness {
            sig: ps_sig,
            messages: msgs_for_PS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_BBS = StatementWitness::SignatureBBS(SignatureBBSWitness {
            sig: bbs_sig,
            messages: msgs_for_BBS_sig.iter().map(|f| f.clone()).collect(),
        });

        let witness_revocation_PS = StatementWitness::Revocation4AryBP(Revocation4AryBP {
            merkle_proof: merkle_proof_vec_PS,
        });

        let witness_revocation_BBS = StatementWitness::Revocation4AryBP(Revocation4AryBP {
            merkle_proof: merkle_proof_vec_BBS,
        });

        let mut statement_witnesses = HashMap::new();
        statement_witnesses.insert(0, witness_PS);
        statement_witnesses.insert(1, witness_BBS);
        statement_witnesses.insert(2, witness_revocation_PS);
        statement_witnesses.insert(3, witness_revocation_BBS);

        let rng = rand::thread_rng();

        // Both the prover and verifier should use this label for creating/verifying proof
        let proof_label = "test_proof_label".as_bytes();
        // Both the prover and verifier should use this label for creating Bulletproof generators
        let bulletproof_label = "test_bulletproof_label".as_bytes();

        let gens: BulletproofsGens;
        let gens_ref = if proof_spec.has_bulletproof_statements() {
            gens = BulletproofsGens::new(bulletproof_label, 2048);
            Some(&gens)
        } else {
            None
        };

        let proof = create_proof::<ThreadRng, PoseidonHashConstraints>(
            proof_spec.clone(),
            Witness {
                statement_witnesses,
            },
            proof_label,
            gens_ref,
        );

        // Verifier's part
        assert!(verify_proof(proof_spec, proof, proof_label, gens_ref));
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
        let stmt_1 = Statement::Equality::<PoseidonHashConstraints>(s1);
        /*build_equalities_old(&mut equalities, &stmt_1);
        assert_eq!(equalities.len(), 1);*/

        let mut s2 = HashSet::new();
        s2.insert(MessageRef {
            statement_idx: 0,
            message_idx: 5,
        });
        let stmt_2 = Statement::Equality::<PoseidonHashConstraints>(s2);
        /*build_equalities_old(&mut equalities, &stmt_2);
        assert_eq!(equalities.len(), 1);*/

        let mut s3 = HashSet::new();
        s3.insert(MessageRef {
            statement_idx: 1,
            message_idx: 5,
        });
        let stmt_3 = Statement::Equality::<PoseidonHashConstraints>(s3);
        /*build_equalities_old(&mut equalities, &stmt_3);
        assert_eq!(equalities.len(), 2);*/

        let mut s4 = HashSet::new();
        s4.insert(MessageRef {
            statement_idx: 1,
            message_idx: 5,
        });
        s4.insert(MessageRef {
            statement_idx: 2,
            message_idx: 6,
        });
        let stmt_4 = Statement::Equality::<PoseidonHashConstraints>(s4);
        /*build_equalities_old(&mut equalities, &stmt_4);
        assert_eq!(equalities.len(), 2);*/

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
        let stmt_5 = Statement::Equality::<PoseidonHashConstraints>(s5);

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
        let stmt_6 = Statement::Equality::<PoseidonHashConstraints>(s6);

        let mut equalities_2 = Vec::<HashSet<MessageRef>>::new();
        let statements = vec![&stmt_1, &stmt_1, &stmt_3, &stmt_4, &stmt_5, &stmt_6];
        build_equalities_for_attributes(&mut equalities_2, statements);
        assert_eq!(equalities_2.len(), 2);
    }

    /*#[test]
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
    }*/
}
