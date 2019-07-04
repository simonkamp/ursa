use bn::{BigNumber, BigNumberContext, BIGNUMBER_1, BIGNUMBER_2};
use errors::prelude::*;

use cl::constants::*;
use cl::hash::get_hash_as_int;
use cl::helpers::*;

pub struct PaillierGroup {
    pub g: BigNumber,
    pub h: BigNumber,
    pub n_by_4: BigNumber,  // n/4
    pub modulus: BigNumber
}

pub struct CSEncPrikey {
    pub x1: Vec<BigNumber>,
    pub x2: BigNumber,
    pub x3: BigNumber
}

pub struct CSEncPubkey {
    pub n: BigNumber,
    pub two_inv_times_2: BigNumber,     // (2^-1 % n) * 2
    pub paillier_group: PaillierGroup,
    pub y1: Vec<BigNumber>,
    pub y2: BigNumber,
    pub y3: BigNumber
}

pub struct CSCiphertext {
    pub u: BigNumber,
    pub e: Vec<BigNumber>,
    pub v: BigNumber,
}

pub struct CSInspector {
    pub pri_key: CSEncPrikey,
    pub pub_key: CSEncPubkey
}

impl PaillierGroup {
    /// Order (modulus) is n^2
    pub fn new(n: &BigNumber, ctx: &mut BigNumberContext) -> UrsaCryptoResult<Self> {
        let modulus = n.sqr(Some(ctx))?;        // n^2
        println!("modulus created");
        let mut n_mul_2 = n.try_clone()?;       // n*2
        n_mul_2.mul_word(2)?;
        let g_prime = modulus.rand_range()?;
        println!("g_prime created");
        let g = g_prime.mod_exp(&n_mul_2, &modulus, Some(ctx))?;
        println!("g created");
        Ok(Self {
            g,
            h: n.increment()?,          // h = n+1
            n_by_4: n.rshift(2)?,       // n/4
            modulus
        })
    }

    /// self.g^exp % self.modulus
    pub fn raise_to_g(&self, exp: &BigNumber, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        self.exponentiate(&self.g, exp, ctx)
    }

    /// self.h^exp % self.modulus
    pub fn raise_to_h(&self, exp: &BigNumber, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        self.exponentiate(&self.h, exp, ctx)
    }

    /// exponentiate in this Paillier group meaning the result is taken modulo this group's order (modulus). base^exp % self.modulus
    pub fn exponentiate(&self, base: &BigNumber, exp: &BigNumber, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        base.mod_exp(exp, &self.modulus, ctx)
    }

    /// base^2 % self.modulus
    pub fn sqr(&self, base: &BigNumber, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        match ctx {
            Some(mut ctx) => {
                base.sqr(Some(&mut ctx))?.modulus(&self.modulus, Some(&mut ctx))
            },
            None => {
                base.sqr(None)?.modulus(&self.modulus, None)
            }
        }
    }

    /// Return a random element modulo the group order, i.e. modulus
    pub fn rand(&self) -> UrsaCryptoResult<BigNumber> {
        self.modulus.rand_range()
    }

    /// Return a random element modulo sqrt(modulo)/4
    pub fn rand_for_enc(&self) -> UrsaCryptoResult<BigNumber> {
        self.n_by_4.rand_range()
    }

    /// if a > (n^2)/2 then n^2 - a else a
    pub fn abs(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        let a = a.modulus(&self.modulus, ctx)?;
        let modulus_by_2 = self.modulus.rshift(1)?;
        if a > modulus_by_2 {
            self.modulus.sub(&a)
        } else {
            Ok(a)
        }
    }
}

impl CSInspector {
    pub fn new (num_messages: usize) -> UrsaCryptoResult<Self> {
        let mut ctx = BigNumber::new_context()?;

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;
        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let two_inv_times_2 = BIGNUMBER_2.inverse(&n, Some(&mut ctx))?.lshift1()?;
        let paillier_group = PaillierGroup::new(&n, &mut ctx)?;
        let n_sqr_by_4 = paillier_group.modulus.rshift(2)?;      // (n^2)/4
        /*let mut n_mul_2 = n.try_clone()?;       // n*2
        n_mul_2.mul_word(2)?;
        let g_prime = paillier_group.random()?;
        let g = g_prime.exp(&n_mul_2, Some(&mut ctx))?;*/
        let mut x1 = Vec::with_capacity(num_messages);
        let mut y1 = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            let x = n_sqr_by_4.rand_range()?;
            //let y = g.exp(&x, Some(&mut ctx))?;
            let y = paillier_group.raise_to_g(&x, Some(&mut ctx))?;
            x1.push(x);
            y1.push(y);
        }
        let x2 = n_sqr_by_4.rand_range()?;
        let x3 = n_sqr_by_4.rand_range()?;
//        let y2 = g.exp(&x2, Some(&mut ctx))?;
        let y2 = paillier_group.raise_to_g(&x2, Some(&mut ctx))?;
//        let y3 = g.exp(&x3, Some(&mut ctx))?;
        let y3 = paillier_group.raise_to_g(&x3, Some(&mut ctx))?;
        Ok(Self {
            pri_key: CSEncPrikey { x1, x2, x3 },
            pub_key: CSEncPubkey { n, two_inv_times_2, paillier_group, y1, y2, y3}
        })
    }

    pub fn decrypt(&self, label: &[u8], ciphertext: &CSCiphertext) -> UrsaCryptoResult<Vec<BigNumber>> {
        if ciphertext.e.len() > self.pri_key.x1.len() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("number of messages {} is more than supported by public key {}", ciphertext.e.len(), self.pri_key.x1.len()),
            ));
        }
        let mut ctx = BigNumber::new_context()?;

        let paillier_group = &self.pub_key.paillier_group;
        if ciphertext.v != paillier_group.abs(&ciphertext.v, Some(&mut ctx))? {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("absolute check failed for v {:?}", &ciphertext.v),
            ));
        }
        let hs = &Self::hash(&ciphertext.u, &ciphertext.e, label)?;
        let hs_x3 = hs.mul(&self.pri_key.x3, Some(&mut ctx))?;
        let hs_x3_x2_times_2 = hs_x3.add(&self.pri_key.x2)?.lshift1()?;
        let u_sqr = paillier_group.exponentiate(&ciphertext.u, &hs_x3_x2_times_2, Some(&mut ctx))?;
        let v_sqr = paillier_group.sqr(&ciphertext.v, Some(&mut ctx))?;
        if v_sqr != u_sqr {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("u^2 != v^2, {:?} != {:?}", &u_sqr, &v_sqr),
            ));
        }
        let mut messages = Vec::<BigNumber>::with_capacity(ciphertext.e.len());
        for i in 0..ciphertext.e.len() {
            let u_x1 = paillier_group.exponentiate(&ciphertext.u, &self.pri_key.x1[i], Some(&mut ctx))?;
            let u_x1_inv = u_x1.inverse(&paillier_group.modulus, Some(&mut ctx))?;
            let e_u_x1_inv = &ciphertext.e[i].mod_mul(&u_x1_inv, &paillier_group.modulus, Some(&mut ctx))?;
            let m_hat = paillier_group.exponentiate(&e_u_x1_inv, &self.pub_key.two_inv_times_2, Some(&mut ctx))?;
            if m_hat.modulus(&self.pub_key.n, Some(&mut ctx))? == *BIGNUMBER_1 {
                let mut m = m_hat.modulus(&paillier_group.modulus, Some(&mut ctx))?;
                m.sub_word(1)?;
                m = m.div(&self.pub_key.n, Some(&mut ctx))?;
                messages.push(m);
            } else {
                return Err(UrsaCryptoError::from_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Decryption failed for message {}", i+1),
                ));
            }
        }

        Ok(messages)
    }

    pub fn encrypt(messages: &[BigNumber], label: &[u8], pub_key: &CSEncPubkey) -> UrsaCryptoResult<CSCiphertext> {
        if messages.len() > pub_key.y1.len() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("number of messages {} is more than supported by public key {}", messages.len(), pub_key.y1.len()),
            ));
        }

        let paillier_group = &pub_key.paillier_group;
        let r = paillier_group.rand_for_enc()?;

        Self::encrypt_using_random_value(&r, messages, label, pub_key)
    }

    /// 1st phase of sigmal protocol. Compute ciphertext and commitments (t values).
    /// Return ciphertext, commitments and random values created during encryption and t value
    pub fn encrypt_and_prove_phase_1(messages: &[BigNumber], blindings: &[BigNumber],
                                     label: &[u8], pub_key: &CSEncPubkey)
        -> UrsaCryptoResult<(CSCiphertext, CSCiphertext, BigNumber, BigNumber)> {
        if messages.len() != blindings.len() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("number of messages {} is not equal to the number of blindings {}", messages.len(), blindings.len()),
            ));
        }

        if messages.len() > pub_key.y1.len() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("number of messages {} is more than supported by public key {}", messages.len(), pub_key.y1.len()),
            ));
        }

        let paillier_group = &pub_key.paillier_group;
        let r = paillier_group.rand_for_enc()?;
        let r_tilde = paillier_group.rand_for_enc()?;
        let ciphertext = Self::encrypt_using_random_value(&r, messages, label, pub_key)?;
        let hash = Self::hash(&ciphertext.u, &ciphertext.e, label)?;
        let ciphertext_t_values = Self::ciphertext_t_values(&r_tilde, &blindings, &hash, pub_key)?;
        Ok((ciphertext, ciphertext_t_values, r, r_tilde))
    }

    /// Return r_hat = r_tilde - r.x
    pub fn encrypt_and_prove_phase_2(r: &BigNumber, r_tilde: &BigNumber,
                                     challenge: &BigNumber, pub_key: &CSEncPubkey,
                                     ctx: Option<&mut BigNumberContext>)
                                     -> UrsaCryptoResult<BigNumber> {
        r_tilde.sub(&(r.mod_mul(&challenge, &pub_key.paillier_group.modulus, ctx)?))
    }

    pub fn encrypt_using_random_value(random_value: &BigNumber, messages: &[BigNumber],
                                      label: &[u8], pub_key: &CSEncPubkey) -> UrsaCryptoResult<CSCiphertext> {
        let mut ctx = BigNumber::new_context()?;

        let u = Self::compute_u(random_value, pub_key, &mut ctx)?;
        let e = Self::compute_e(messages, random_value, pub_key, &mut ctx)?;
        let hash = Self::hash(&u, &e, label)?;
        let v = Self::compute_v(random_value, &hash, pub_key, &mut ctx, true)?;
        Ok(CSCiphertext { u, e, v})
    }

    pub fn ciphertext_t_values(random_value: &BigNumber, messages: &[BigNumber],
                               hash: &BigNumber, pub_key: &CSEncPubkey) -> UrsaCryptoResult<CSCiphertext> {
        let mut ctx = BigNumber::new_context()?;
        let messages: Vec<_>= messages.iter().map(|m| m.lshift1().unwrap()).collect();
        let random_value = random_value.lshift1()?;
        let u = Self::compute_u(&random_value, pub_key, &mut ctx)?;
        let e = Self::compute_e(&messages, &random_value, pub_key, &mut ctx)?;
        let v = Self::compute_v(&random_value, hash, pub_key, &mut ctx, false)?;
        Ok(CSCiphertext { u, e, v})
    }

    pub fn reconstruct_blindings_ciphertext(ciphertext: &CSCiphertext,
                                          message_s_values: &[BigNumber], r_hat: &BigNumber, challenge: &BigNumber,
                                          label: &[u8], pub_key: &CSEncPubkey) -> UrsaCryptoResult<CSCiphertext> {
        if message_s_values.len() > pub_key.y1.len() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("number of messages {} is more than supported by public key {}", message_s_values.len(), pub_key.y1.len()),
            ));
        }

        let challenge = &(challenge.lshift1()?);
        let r_hat = &(r_hat.lshift1()?);

        let paillier_group = &pub_key.paillier_group;
        let mut ctx = BigNumber::new_context()?;

        let u_c = paillier_group.exponentiate(&ciphertext.u, challenge, Some(&mut ctx))?;
        let g_r_hat = paillier_group.raise_to_g(r_hat, Some(&mut ctx))?;
        let u_blinded = u_c.mod_mul(&g_r_hat, &paillier_group.modulus, Some(&mut ctx))?;
        let mut e_blinded = vec![];
        for i in 0..message_s_values.len() {
            let e_c = paillier_group.exponentiate(&ciphertext.e[i], challenge, Some(&mut ctx))?;
            let y_r_hat = paillier_group.exponentiate(&pub_key.y1[i], r_hat, Some(&mut ctx))?;
            let h_m_hat = paillier_group.raise_to_h(&(message_s_values[i].lshift1()?), Some(&mut ctx))?;
            e_blinded.push(
                e_c.mod_mul(&y_r_hat, &paillier_group.modulus, Some(&mut ctx))?
                    .mod_mul(&h_m_hat, &paillier_group.modulus, Some(&mut ctx))?
            );
        }
        let v_c = paillier_group.exponentiate(&ciphertext.v, challenge, Some(&mut ctx))?;
        let y3_hs = paillier_group.exponentiate(&pub_key.y3, &Self::hash(&ciphertext.u, &ciphertext.e, label)?, Some(&mut ctx))?;
        let y2_y3_hs = &pub_key.y2.mod_mul(&y3_hs, &paillier_group.modulus, Some(&mut ctx))?;
        let y2_y3_hs_r_hat = paillier_group.exponentiate(&y2_y3_hs, r_hat, Some(&mut ctx))?;
        let v_blinded = v_c.mod_mul(&y2_y3_hs_r_hat, &paillier_group.modulus, Some(&mut ctx))?;
        Ok(CSCiphertext {
            u: u_blinded,
            e: e_blinded,
            v: v_blinded
        })
    }

    fn compute_u(random_value: &BigNumber, pub_key: &CSEncPubkey, mut ctx: &mut BigNumberContext) -> UrsaCryptoResult<BigNumber> {
        pub_key.paillier_group.raise_to_g(random_value, Some(&mut ctx))
    }

    fn compute_e(messages: &[BigNumber], random_value: &BigNumber, pub_key: &CSEncPubkey,
                     mut ctx: &mut BigNumberContext) -> UrsaCryptoResult<Vec<BigNumber>> {
        let paillier_group = &pub_key.paillier_group;
        let mut e = Vec::with_capacity(messages.len());
        for i in 0..messages.len() {
            let y = paillier_group.exponentiate(&pub_key.y1[i], random_value, Some(&mut ctx))?;
            let h_m = paillier_group.raise_to_h(&messages[i], Some(&mut ctx))?;
            e.push(y.mod_mul(&h_m, &paillier_group.modulus, Some(&mut ctx))?);
        }
        Ok(e)
    }

    fn compute_v(random_value: &BigNumber, hash: &BigNumber, pub_key: &CSEncPubkey,
                 mut ctx: &mut BigNumberContext, take_abs: bool) -> UrsaCryptoResult<BigNumber> {
        let paillier_group = &pub_key.paillier_group;
        let y3_hs = paillier_group.exponentiate(&pub_key.y3, hash, Some(&mut ctx))?;
        let y2_y3_hs = &pub_key.y2.mod_mul(&y3_hs, &paillier_group.modulus, Some(&mut ctx))?;
        let y2_y3_hs_r = paillier_group.exponentiate(&y2_y3_hs, random_value, Some(&mut ctx))?;
        if take_abs {
            paillier_group.abs(&y2_y3_hs_r, Some(&mut ctx))
        } else {
            Ok(y2_y3_hs_r)
        }
    }

    fn hash(u: &BigNumber, e: &[BigNumber], label: &[u8]) -> UrsaCryptoResult<BigNumber> {
        let mut arr = vec![u.to_bytes()?];
        for b in e {
            arr.push(b.to_bytes()?)
        }
        arr.push(label.to_vec());
        get_hash_as_int(&arr)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn paillier_abs() {
        let mut ctx = BigNumber::new_context().unwrap();

        let p_safe = generate_safe_prime(LARGE_PRIME).unwrap();
        let q_safe = generate_safe_prime(LARGE_PRIME).unwrap();
//        let p_safe = BigNumber::from_dec("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623").unwrap();
//        let q_safe = BigNumber::from_dec("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623").unwrap();
        let n = p_safe.mul(&q_safe, Some(&mut ctx)).unwrap();
        println!("n created");
        let paillier_group = PaillierGroup::new(&n, &mut ctx).unwrap();

        println!("Paillier group created");

        for _ in 0..10 {
            let v = paillier_group.rand().unwrap();
            println!("v created");
            let abs_v = paillier_group.abs(&v, Some(&mut ctx)).unwrap();
            println!("abs(v) created");
            let v_sqr = paillier_group.sqr(&v, Some(&mut ctx)).unwrap();
//        let v_sqr = v.sqr(Some(&mut ctx)).unwrap();
            println!("v^2 created");
            let abs_v_sqr = paillier_group.sqr(&abs_v, Some(&mut ctx)).unwrap();
//        let abs_v_sqr = abs_v.sqr(Some(&mut ctx)).unwrap();
            println!("abs(v)^2 created");
            assert_eq!(v_sqr, abs_v_sqr);
        }
    }

    #[test]
    fn cs_encryption_smaller_public_key() {
        // Public key supports encryption of only 1 message but encryption of 2 messages is attempted
        let inspector = CSInspector::new(1).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap(), inspector.pub_key.n.rand_range().unwrap()];
        assert!(CSInspector::encrypt(&messages, "test".as_bytes(), &inspector.pub_key).is_err())
    }

    #[test]
    fn cs_encryption_single_message() {
        let inspector = CSInspector::new(1).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap()];
        let ciphertext = CSInspector::encrypt(&messages, "test".as_bytes(), &inspector.pub_key).unwrap();
        let decryped_messages = inspector.decrypt("test".as_bytes(), &ciphertext).unwrap();
        assert_eq!(decryped_messages, messages);
    }

    #[test]
    fn cs_encryption_multiple_messages() {
        let num_messages = 10;
        let inspector = CSInspector::new(num_messages).unwrap();
        let messages: Vec<_> = (0..num_messages).map(|_| inspector.pub_key.n.rand_range().unwrap()).collect();
        let ciphertext = CSInspector::encrypt(&messages, "test2".as_bytes(), &inspector.pub_key).unwrap();
        let decryped_messages = inspector.decrypt("test2".as_bytes(), &ciphertext).unwrap();
        assert_eq!(decryped_messages, messages);
    }

    #[test]
    fn cs_encryption_single_message_bigger_public_key() {
        // Public key supports encryption of 2 messages but only 1 message is encrypted
        let inspector = CSInspector::new(2).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap()];
        let ciphertext = CSInspector::encrypt(&messages, "test".as_bytes(), &inspector.pub_key).unwrap();
        let decryped_messages = inspector.decrypt("test".as_bytes(), &ciphertext).unwrap();
        assert_eq!(decryped_messages, messages);
    }

    #[test]
    fn cs_decryption_smaller_public_key() {
        // // Public key supports encryption of only 1 message but decryption of 2 message ciphertext is attempted
        let mut inspector = CSInspector::new(2).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap(), inspector.pub_key.n.rand_range().unwrap()];
        let ciphertext = CSInspector::encrypt(&messages, "test".as_bytes(), &inspector.pub_key).unwrap();

        // Make public key smaller
        inspector.pri_key.x1.pop();
        assert!(inspector.decrypt("test".as_bytes(), &ciphertext).is_err());
    }

    #[test]
    fn prove_cs_encryption_single_message() {
        let mut ctx = BigNumber::new_context().unwrap();

        let inspector = CSInspector::new(1).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap()];
        let ciphertext = CSInspector::encrypt(&messages, "test".as_bytes(), &inspector.pub_key).unwrap();
        let decryped_messages = inspector.decrypt("test".as_bytes(), &ciphertext).unwrap();
        assert_eq!(decryped_messages, messages);

        // Message blinding are m_tilde values and they will be created by the main proving protocol not this verifiable encryption module
        let blindings = vec![inspector.pub_key.n.rand_range().unwrap()];

        let start = Instant::now();
        // Proving starts, create t values
        let (ciphertext, blindings_ciphertext, r, r_tilde) = CSInspector::encrypt_and_prove_phase_1(
            &messages, &blindings, "test2".as_bytes(), &inspector.pub_key).unwrap();

        // The verifier sends this challenge or this challenge can be created by hashing `blindings_ciphertext`
        let challenge = inspector.pub_key.n.rand_range().unwrap();

        // Proving finishes, create s values
        let r_hat = CSInspector::encrypt_and_prove_phase_2(&r, &r_tilde, &challenge,
                                                           &inspector.pub_key, Some(&mut ctx)).unwrap();
        println!("Proving time for CS verifiable encryption with single message is: {:?}", start.elapsed());

        // m_hat will be created by the main proving protocol not this verifiable encryption module
        let m_hat = blindings[0].sub(&(messages[0].mod_mul(&challenge, &inspector.pub_key.paillier_group.modulus,
                                                           Some(&mut ctx)).unwrap())).unwrap();

        let start = Instant::now();
        // Next part is done by verifier
        let blindings_ciphertext_1 = CSInspector::reconstruct_blindings_ciphertext(
            &ciphertext, &vec![m_hat], &r_hat, &challenge,
            "test2".as_bytes(), &inspector.pub_key).unwrap();

        assert_eq!(blindings_ciphertext.u, blindings_ciphertext_1.u);
        assert_eq!(blindings_ciphertext.e[0], blindings_ciphertext_1.e[0]);
        assert_eq!(blindings_ciphertext.v, blindings_ciphertext_1.v);
        println!("Verification time for CS verifiable encryption with single message is: {:?}", start.elapsed());
    }

    #[test]
    fn prove_cs_encryption_smaller_public_key() {
        let inspector = CSInspector::new(1).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap(), inspector.pub_key.n.rand_range().unwrap()];
        let blindings = vec![inspector.pub_key.n.rand_range().unwrap(), inspector.pub_key.n.rand_range().unwrap()];
        assert!(CSInspector::encrypt_and_prove_phase_1(&messages, &blindings,
                                                       "test2".as_bytes(), &inspector.pub_key).is_err());
    }

    #[test]
    fn prove_cs_encryption_incorrect_number_of_blindings() {
        // No of blindings should be same as number of messages
        let inspector = CSInspector::new(2).unwrap();
        let messages = vec![inspector.pub_key.n.rand_range().unwrap(), inspector.pub_key.n.rand_range().unwrap()];

        // Less blindings
        let blindings_1 = vec![inspector.pub_key.n.rand_range().unwrap()];
        assert!(CSInspector::encrypt_and_prove_phase_1(&messages, &blindings_1,
                                                       "test2".as_bytes(), &inspector.pub_key).is_err());

        // More blindings
        let blindings_2 = vec![inspector.pub_key.n.rand_range().unwrap(),
                               inspector.pub_key.n.rand_range().unwrap(),
                               inspector.pub_key.n.rand_range().unwrap()];
        assert!(CSInspector::encrypt_and_prove_phase_1(&messages, &blindings_2,
                                                       "test2".as_bytes(), &inspector.pub_key).is_err());
    }

    #[test]
    fn prove_cs_encryption_multiple_messages() {
        let mut ctx = BigNumber::new_context().unwrap();

        let num_messages = 10;

        let inspector = CSInspector::new(num_messages).unwrap();
        let messages: Vec<_> = (0..num_messages).map(|_| inspector.pub_key.n.rand_range().unwrap()).collect();
        let ciphertext = CSInspector::encrypt(&messages, "test2".as_bytes(), &inspector.pub_key).unwrap();
        let decryped_messages = inspector.decrypt("test2".as_bytes(), &ciphertext).unwrap();
        assert_eq!(decryped_messages, messages);

        let blindings: Vec<_> = (0..num_messages).map(|_| inspector.pub_key.n.rand_range().unwrap()).collect();

        let start = Instant::now();
        let (ciphertext, blindings_ciphertext, r, r_tilde) = CSInspector::encrypt_and_prove_phase_1(
            &messages, &blindings, "test2".as_bytes(), &inspector.pub_key).unwrap();

        let challenge = inspector.pub_key.n.rand_range().unwrap();

        let r_hat = CSInspector::encrypt_and_prove_phase_2(&r, &r_tilde, &challenge,
                                                           &inspector.pub_key, Some(&mut ctx)).unwrap();
        println!("Proving time for CS verifiable encryption with {} messages is: {:?}", num_messages, start.elapsed());

        let mut m_hats = vec![];
        for i in 0..num_messages {
            let m_hat = blindings[i].sub(&(messages[i].mod_mul(&challenge, &inspector.pub_key.paillier_group.modulus,
                                                               Some(&mut ctx)).unwrap())).unwrap();
            m_hats.push(m_hat);
        }

        let start = Instant::now();
        let blindings_ciphertext_1 = CSInspector::reconstruct_blindings_ciphertext(
            &ciphertext, &m_hats, &r_hat, &challenge,
            "test2".as_bytes(), &inspector.pub_key).unwrap();

        assert_eq!(blindings_ciphertext.u, blindings_ciphertext_1.u);
        for i in 0..num_messages {
            assert_eq!(blindings_ciphertext.e[i], blindings_ciphertext_1.e[i]);
        }
        assert_eq!(blindings_ciphertext.v, blindings_ciphertext_1.v);
        println!("Verification time for CS verifiable encryption with {} messages is: {:?}", num_messages, start.elapsed());
    }
}