use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::{Hash, Tag};
use std::array::TryFromSliceError;

use secp256k1::{SecretKey, PublicKey, Keypair};
use secp256k1::ellswift::{Party, ElligatorSwift};
use secp256k1::schnorr::Signature;
use secp256k1::rand;
use secp256k1::rand::Rng;

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key as ChaChaKey};

use bls12_381::{Gt, Scalar, fp::Fp, fp2::Fp2, fp6::Fp6, fp12::Fp12};
use group::Group;
use std::ops::Deref;

use ark_bls12_381::{G1Projective, G1Affine, G2Projective, G2Affine, Fq12, Fq6, Fq2, Fq, Fr, Bls12_381};
use ark_ff::fields::Field;
use ark_ff::{One, Zero, PrimeField};
use ark_ec::{PrimeGroup, CurveGroup, AdditiveGroup};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};

trait Serialize {fn serialize(&self) -> Vec<u8>;}
impl<S: CanonicalSerialize> Serialize for S {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        self.serialize_compressed(&mut serialized);
        serialized
    }
}

trait Deserialize {fn deserialize(b: &[u8]) -> Result<Self, SerializationError> where Self: Sized;}
impl<S: CanonicalDeserialize> Deserialize for S {
    fn deserialize(b: &[u8]) -> Result<Self, SerializationError> {
        S::deserialize_compressed(b)
    }
}

pub fn to_compressed(gt: &Fq12) -> Vec<u8> {
    ((Fq6::one() + gt.c0) * gt.c1.inverse().unwrap()).serialize()
}

pub fn from_compressed(b: &[u8]) -> Result<Fq12, SerializationError> {
    let beta = Fq6::deserialize(b)?;
    let v = Fq6{
        c0: Fq2::zero(),
        c1: Fq2 { c0: Fq::one(), c1: Fq::zero() },
        c2: Fq2::zero(),
    };
    let beta_square = beta.square();
    let denom = beta_square - v;
    let inv_denom = denom.inverse().expect("Invalid beta: denominator zero");
    let c0 = (beta_square + v) * inv_denom;
    let mut c1 = beta.double() * inv_denom;
    Ok(Fq12 { c0, c1 })
}

const MIDSTATE: Midstate = Midstate::hash_tag(b"orange_name");

#[derive(Debug)]
pub enum Error {
    ChaChaError(chacha20_poly1305::Error),
    InvalidCipherText,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}
impl std::error::Error for Error {}
impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Error {Error::InvalidCipherText}
}
impl From<chacha20_poly1305::Error> for Error {
    fn from(e: chacha20_poly1305::Error) -> Error {Error::ChaChaError(e)}
}

struct HIBETag;
impl Tag for HIBETag {fn engine() -> HashEngine {HashEngine::from_midstate(MIDSTATE)}}
type HIBEHash = Hash<HIBETag>;

fn get_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {loop {
    if let Some(x) = Fr::from_random_bytes(&rng.random::<[u8; 32]>()) {
        break x;
    }
}}

fn get_scalar2<R: Rng + ?Sized>(rng: &mut R) -> (Scalar, Fr) {loop {
    let b = rng.random::<[u8; 32]>();
    if let Some(x) = Scalar::from_bytes(&b).into_option() {
        break (x, Fr::from_random_bytes(&b).unwrap());
    }
}}

#[derive(Clone, Copy, Debug)]
pub struct MasterPub {
    g1_h: G1Affine,
    egg: Fq12,
}

impl MasterPub {
    fn encrypt<R: Rng + ?Sized>(&self, rng: &mut R, id: &[Fr], mut p: Vec<u8>) -> Vec<u8> {
        let ms = get_scalar(rng);
        let m = self.egg.pow(ms.into_bigint());
        println!("m: {:?}", m);

        let s = get_scalar(rng);
        let a = m.pow(s.into_bigint());

        let am = a - (self.egg-self.egg.pow(s.into_bigint()));
        assert_eq!(am, m);

        let b = (G2Projective::generator()*s).into_affine();
        let c = (0..id.len()).map(|x| ((self.g1_h*id[x])*s).into_affine()).collect();

        let cipher = Cipher{a, b, c};
        let shared = HIBEHash::hash(&m.serialize());
        println!("shared: {:?}", shared);
        let key = ChaChaKey::new(*shared.as_ref());
        [
            cipher.to_vec(),
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut p, None).to_vec(),
            p
        ].concat()
    }
}

pub struct MasterKey{
    h: Fr,
    g2s: Fr,
    a: Fr,
    key: Key
}
impl MasterKey {
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let g2s = get_scalar(rng);
        let a = get_scalar(rng);
        let h = get_scalar(rng);

        let key = Key{
            d0: ((G1Projective::generator()*g2s)*a).into_affine(),
            dx: vec![]
        };

        MasterKey{
            h, g2s, a, key 
        }
    }

    pub fn master_pub(&self) -> MasterPub {
        let p = G2Projective::generator();
        let g = G1Projective::generator();
        let g1 = g*self.a;
        let pa = p*self.a;
        let g1_h = (g1*self.h).into_affine();

        let g2 = g*self.g2s;
        let egg = Bls12_381::pairing(&g2.into_affine(), &pa.into_affine()).0;
        MasterPub{g1_h, egg}
    }

    pub fn to_key(self) -> Key {self.key}
}
impl Deref for MasterKey {type Target = Key; fn deref(&self) -> &Key {&self.key}}

pub struct Key {
    d0: G1Affine,
    dx: Vec<G2Affine>
}
impl Key {
    fn derive<R: Rng + ?Sized>(&self, rng: &mut R, master_pub: &MasterPub, id: &[Fr]) -> Key {
        let r = (0..id.len()).map(|_| get_scalar(rng)).collect::<Vec<_>>();
        let d0 = (0..id.len()).fold(self.d0, |key, x|
            (key + (master_pub.g1_h * id[x]) * r[x]).into_affine()
        );
        let dk = (0..id.len()).map(|x| (G2Projective::generator()*r[x]).into_affine()).collect();
        Key{d0, dx: [self.dx.clone(), dk].concat()}
    }

    fn decrypt(&self, p: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::from_slice(p)?;
        let cipher_size = cipher.size();
        let Cipher{a, b, c} = cipher;
        let ecd = Bls12_381::final_exponentiation(Bls12_381::multi_miller_loop(
            c, self.dx.iter()
        )).unwrap().0;

        let bd0 = Bls12_381::pairing(&self.d0, &b).0;
        let m = a+(ecd + -bd0);
        println!("m: {:?}", m);

        let shared = HIBEHash::hash(&m.serialize());
        println!("shared: {:?}", shared);
        let key = ChaChaKey::new(*shared.as_ref());

        let tag: [u8; 16] = p[cipher_size..cipher_size+16].try_into()?;
        let mut payload = p[cipher_size+16..].to_vec();

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None)?;
        Ok(payload)
    }
}

#[derive(Debug, PartialEq)]
struct Cipher {
    a: Fq12,
    b: G2Affine,
    c: Vec<G1Affine>
}
impl Cipher {
    fn size(&self) -> usize {8+288+96+(self.c.len()*48)}

    fn to_vec(&self) -> Vec<u8> {
        
        [
            (self.c.len() as u64).to_be_bytes().to_vec(),
            to_compressed(&self.a),
            self.b.serialize(),
            self.c.iter().flat_map(|c| c.serialize()).collect()
        ].concat()
    }

    fn from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        let c_len = u64::from_be_bytes(slice[0..8].try_into()?) as usize;
        Ok(Cipher{
            a: from_compressed(&slice[8..8+288]).unwrap(),
            b: G2Affine::deserialize(slice[8+288..8+288+96].try_into()?).unwrap(),
            c: (0..c_len).map(|i| Ok(G1Affine::deserialize(
                slice[8+288+96+(i*48)..8+288+96+(i*48)+48].try_into()?
            ).unwrap())).collect::<Result<_, TryFromSliceError>>()?
        })
    }
}

#[test]
pub fn encryption() {
    let mut rng = rand::rng();

    let (a, b) = get_scalar2(&mut rng);
    let (_, c) = get_scalar2(&mut rng);
    let kgt = Bls12_381::pairing(&G1Projective::generator(), &G2Projective::generator());
    let _kgt_b = (kgt*b).0;

    let kgt_b = from_compressed(&to_compressed(&_kgt_b)).unwrap();
    assert_eq!(_kgt_b, kgt_b);

  //let sign = bool::from(gt_a.0.c1.lexicographically_largest());

  //let beta = (Fp6::one() + gt_a.0.c0) * gt_a.0.c1.invert().unwrap();
  //let dgt_a = {
  //    let beta_square = beta.square();
  //    let denom = beta_square - V;
  //    let inv_denom = denom.invert().expect("Invalid beta: denominator zero");
  //    let c0 = (beta_square + V) * inv_denom;
  //    let mut c1 = beta.double() * inv_denom;
  //    if true {
  //        c1 = -c1;
  //    }
  //    Gt(Fp12 { c0: c0, c1 })
  //};




  //let beta = (Fq6::one() + kgt_b.0.c0) * kgt_b.0.c1.inverse().unwrap();
  //let dkgt_b = {
  //    let v = v();
  //    let beta_square = beta.square();
  //    let denom = beta_square - v;
  //    let inv_denom = denom.inverse().expect("Invalid beta: denominator zero");
  //    let c0 = (beta_square + v) * inv_denom;
  //    let mut c1 = beta.double() * inv_denom;
  //    if true {
  //        c1 = -c1;
  //    }
  //    Fq12 { c0: c0, c1 }
  //};

  //panic!("{sign}\n\n {gt_a:?}\n\n {dgt_a:?}, \n\n{dkgt_b}");
    //panic!("{gt_a:?}, \n\n{kgt_b:?}");
    //panic!("{igt_a:?}, \n\n{ikgt_b}");
    //panic!("{gt_a:?}, \n\n{kgt_b}");






    //Setup
    let master_key = MasterKey::new(&mut rng);
    let master_pub = master_key.master_pub();
    let id1 = get_scalar(&mut rng);
    let id2 = get_scalar(&mut rng);
    let id3 = get_scalar(&mut rng);

    //KeyGen
    let key1 = master_key.derive(&mut rng, &master_pub, &[id1]);
    let key2 = key1.derive(&mut rng, &master_pub, &[id2]);
    let key3 = key2.derive(&mut rng, &master_pub, &[id3]);

    let keyf = master_key.derive(&mut rng, &master_pub, &[id1, id2, id3]);

    //Encrypt
    let m = vec![29, 49, 47];
    let c = master_pub.encrypt(&mut rng, &[id1, id2, id3], m.clone());
    let cm = master_pub.encrypt(&mut rng, &[], m.clone());

    //Decrypt
    let dm = key3.decrypt(&c).unwrap();
    let dm_ = keyf.decrypt(&c).unwrap();
    let dmm = master_key.decrypt(&cm).unwrap();

    assert_eq!(m, dm);
    assert_eq!(m, dm_);
    assert_eq!(m, dmm);
}
