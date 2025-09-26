use std::array::TryFromSliceError;

use serde::{Serialize, Deserialize};
use serde::ser::{Serializer, Error as _Error};
use serde::de::{Deserializer, Error as __Error};

use crate::OrangeHash;

use secp256k1::rand::Rng;

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key as ChaChaKey};

use std::ops::Deref;

use ark_bls12_381::{G1Projective, G1Affine, G2Projective, G2Affine, Fq12, Fq6, Fq2, Fq, Fr, Bls12_381};
use ark_ff::fields::Field;
use ark_ff::{One, Zero, PrimeField, BigInt};
use ark_ec::{PrimeGroup, CurveGroup, AdditiveGroup};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};

const SIGNING: Fr = Fr::new(BigInt::one());

trait _Serialize {fn serialize_c(&self) -> Result<Vec<u8>, SerializationError>;}
impl<S: CanonicalSerialize> _Serialize for S {
    fn serialize_c(&self) -> Result<Vec<u8>, SerializationError> {
        let mut serialized = Vec::new();
        self.serialize_compressed(&mut serialized)?;
        Ok(serialized)
    }
}

trait _Deserialize {fn deserialize_c(b: &[u8]) -> Result<Self, SerializationError> where Self: Sized;}
impl<S: CanonicalDeserialize> _Deserialize for S {
    fn deserialize_c(b: &[u8]) -> Result<Self, SerializationError> {
        S::deserialize_compressed(b)
    }
}

fn path_to_ids<H: std::hash::Hash>(path: &[H]) -> Vec<Fr> {
    path.into_iter().map(|p|
        Fr::from_be_bytes_mod_order(OrangeHash::hash(&crate::HashReader::read(p)).as_ref())
    ).collect::<Vec<_>>()
}

fn to_compressed(gt: &Fq12) -> Result<Vec<u8>, SerializationError> {
    ((Fq6::one() + gt.c0) * gt.c1.inverse().unwrap()).serialize_c()
}

fn from_compressed(b: &[u8]) -> Result<Fq12, SerializationError> {
    let beta = Fq6::deserialize_c(b)?;
    let v = Fq6{
        c0: Fq2::zero(),
        c1: Fq2 { c0: Fq::one(), c1: Fq::zero() },
        c2: Fq2::zero(),
    };
    let beta_square = beta.square();
    let denom = beta_square - v;
    let inv_denom = denom.inverse().expect("Invalid beta: denominator zero");
    let c0 = (beta_square + v) * inv_denom;
    let c1 = beta.double() * inv_denom;
    Ok(Fq12 { c0, c1 })
}

#[derive(Debug)]
pub enum Error {
    ChaChaError(chacha20_poly1305::Error),
    SerializationError(SerializationError),
    InvalidCiphertext,
    /// Cannot derive Id == 1 reserved for signing keys
    SigningDerivation,
    InvalidSignature
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}
impl std::error::Error for Error {}
impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Error {Error::InvalidCiphertext}
}
impl From<chacha20_poly1305::Error> for Error {
    fn from(e: chacha20_poly1305::Error) -> Error {Error::ChaChaError(e)}
}
impl From<SerializationError> for Error {
    fn from(e: SerializationError) -> Error {Error::SerializationError(e)}
}

fn get_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {loop {
    if let Some(x) = Fr::from_random_bytes(&rng.random::<[u8; 32]>()) {
        break x;
    }
}}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterPub {
    g1_h: G1Affine,
    egg: Fq12,
}

impl Serialize for MasterPub {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.g1_h.serialize_c().map_err(S::Error::custom)?,
            to_compressed(&self.egg).map_err(S::Error::custom)?
        ).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MasterPub {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (g1_h, egg) = <(Vec<u8>, Vec<u8>)>::deserialize(deserializer)?;
        Ok(MasterPub {
            g1_h: G1Affine::deserialize_c(&g1_h).map_err(D::Error::custom)?,
            egg: from_compressed(&egg).map_err(D::Error::custom)?,
        })
    }
}

impl MasterPub {
    pub fn encrypt<H: std::hash::Hash>(&self, path: &[H], mut p: Vec<u8>) -> Result<Vec<u8>, Error> {
        let id = path_to_ids(path); 
        let (m, cipher) = self.get_cipher(&id);
        let shared = OrangeHash::hash(&m.serialize_c()?);
        let key = ChaChaKey::new(*shared.as_ref());
        Ok([
            cipher.to_vec()?,
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut p, None).to_vec(),
            p
        ].concat())
    }

    pub fn verify<H: std::hash::Hash>(&self, path: &[H], signature: &Signature, m: &[u8]) -> Result<(), Error> {
        let id = &path_to_ids(path); 
        let id = [id as &[Fr], &[SIGNING, Fr::from_be_bytes_mod_order(OrangeHash::hash(m).as_ref())]].concat();
        let (m, c) = self.get_cipher(&id);
        if m != signature.0.get_m(&c) {Err(Error::InvalidSignature)?}
        Ok(())
    }

    fn get_cipher(&self, id: &[Fr]) -> (Fq12, Cipher) {
        let mut rng = secp256k1::rand::rng();
        let ms = get_scalar(&mut rng);
        let m = self.egg.pow(ms.into_bigint());

        let s = get_scalar(&mut rng);
        let a = self.egg.pow(s.into_bigint())*m;

        let b = (G2Projective::generator()*s).into_affine();
        let c = (0..id.len()).map(|x| ((self.g1_h*id[x])*s).into_affine()).collect();

        (m, Cipher{a, b, c})
    }
}

pub struct MasterKey{
    h: Fr,
    g2s: Fr,
    a: Fr,
    key: SecretKey
}
impl MasterKey {
    pub fn new() -> Self {
        let mut rng = secp256k1::rand::rng();
        let g2s = get_scalar(&mut rng);
        let a = get_scalar(&mut rng);
        let h = get_scalar(&mut rng);
        let key = Self::get_key(&g2s, &a);
        MasterKey{h, g2s, a, key}
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

    pub fn to_key(self) -> SecretKey {self.key}

    fn get_key(g2s: &Fr, a: &Fr) -> SecretKey {SecretKey{
        d0: ((G1Projective::generator()*g2s)*a).into_affine(),
        dx: vec![]
    }}
}
impl Deref for MasterKey {type Target = SecretKey; fn deref(&self) -> &SecretKey {&self.key}}

impl Serialize for MasterKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.h.serialize_c().map_err(S::Error::custom)?,
            self.g2s.serialize_c().map_err(S::Error::custom)?, 
            self.a.serialize_c().map_err(S::Error::custom)?
        ).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MasterKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (h, g2s, a) = <(Vec<u8>, Vec<u8>, Vec<u8>)>::deserialize(deserializer)?;
        let h = Fr::deserialize_c(&h).map_err(D::Error::custom)?;
        let g2s = Fr::deserialize_c(&g2s).map_err(D::Error::custom)?;
        let a = Fr::deserialize_c(&a).map_err(D::Error::custom)?;
        let key = Self::get_key(&g2s, &a);
        Ok(MasterKey{h, g2s, a, key})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey {
    d0: G1Affine,
    dx: Vec<G2Affine>
}
impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.d0.serialize_c().map_err(S::Error::custom)?,
            self.dx.iter().map(|dx|
                dx.serialize_c().map_err(S::Error::custom)
            ).collect::<Result<Vec<Vec<u8>>, S::Error>>()?
        ).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (d0, dx) = <(Vec<u8>, Vec<Vec<u8>>)>::deserialize(deserializer)?;
        Ok(SecretKey{
            d0: G1Affine::deserialize_c(&d0).map_err(D::Error::custom)?,
            dx: dx.into_iter().map(|dx|
                G2Affine::deserialize_c(&dx).map_err(D::Error::custom)
            ).collect::<Result<_, D::Error>>()?,
        })
    }
}
impl SecretKey {
    pub fn derive<H: std::hash::Hash>(&self, master_pub: &MasterPub, path: &[H]) -> Result<Self, Error> {
        let id = path_to_ids(path); 
        if id.iter().any(|id| id == &SIGNING) {Err(Error::SigningDerivation)?;}
        Ok(self.unchecked_derive(master_pub, &id))
    }

    pub fn decrypt(&self, p: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::from_slice(p)?;
        let cipher_size = cipher.size();
        let m = self.get_m(&cipher);

        let shared = OrangeHash::hash(&m.serialize_c()?);
        let key = ChaChaKey::new(*shared.as_ref());

        let tag: [u8; 16] = p[cipher_size..cipher_size+16].try_into()?;
        let mut payload = p[cipher_size+16..].to_vec();

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None)?;
        Ok(payload)
    }

    pub fn sign(&self, master_pub: &MasterPub, m: &[u8]) -> Signature {
        Signature(
            self.unchecked_derive(master_pub, &[SIGNING, Fr::from_be_bytes_mod_order(OrangeHash::hash(m).as_ref())])
        )
    }

    fn unchecked_derive(&self, master_pub: &MasterPub, id: &[Fr]) -> SecretKey {
        let r = (0..id.len()).map(|_| get_scalar(&mut secp256k1::rand::rng())).collect::<Vec<_>>();
        let d0 = (0..id.len()).fold(self.d0, |key, x|
            (key + (master_pub.g1_h * id[x]) * r[x]).into_affine()
        );
        let dk = (0..id.len()).map(|x| (G2Projective::generator()*r[x]).into_affine()).collect();
        SecretKey{d0, dx: [self.dx.clone(), dk].concat()}
    }

    fn get_m(&self, c: &Cipher) -> Fq12 {
        let Cipher{a, b, c} = c;
        let ecd = Bls12_381::final_exponentiation(Bls12_381::multi_miller_loop(
            c, self.dx.iter()
        )).unwrap().0;

        let bd0 = Bls12_381::pairing(&self.d0, b).0;
        a*(ecd * bd0.inverse().unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signature(SecretKey);

#[derive(Debug, PartialEq)]
struct Cipher {
    a: Fq12,
    b: G2Affine,
    c: Vec<G1Affine>
}
impl Cipher {
    fn size(&self) -> usize {8+288+96+(self.c.len()*48)}

    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok([
            (self.c.len() as u64).to_be_bytes().to_vec(),
            to_compressed(&self.a)?,
            self.b.serialize_c()?,
            self.c.iter().map(|c| c.serialize_c()).collect::<Result<Vec<Vec<u8>>, SerializationError>>()?.concat()
        ].concat())
    }

    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() < 8 {Err(Error::InvalidCiphertext)?}
        let c_len = u64::from_be_bytes(slice[0..8].try_into()?) as usize;
        if slice.len() < 8+288+96+(c_len*48) {Err(Error::InvalidCiphertext)?}
        Ok(Cipher{
            a: from_compressed(&slice[8..8+288])?,
            b: G2Affine::deserialize_c(slice[8+288..8+288+96].try_into().unwrap())?,
            c: (0..c_len).map(|i| Ok(G1Affine::deserialize_c(
                slice[8+288+96+(i*48)..8+288+96+(i*48)+48].try_into().unwrap()
            )?)).collect::<Result<_, Error>>()?
        })
    }
}

#[test]
pub fn encryption() {
    let mut rng = secp256k1::rand::rng();

    //Setup
    let master_key = MasterKey::new();
    let master_pub = master_key.master_pub();
    let id1 = get_scalar(&mut rng);
    let id2 = get_scalar(&mut rng);
    let id3 = get_scalar(&mut rng);

    //KeyGen
    let key1 = master_key.derive(&master_pub, &[id1]).unwrap();
    let key2 = key1.derive(&master_pub, &[id2]).unwrap();
    let key3 = key2.derive(&master_pub, &[id3]).unwrap();

    let keyf = master_key.derive(&master_pub, &[id1, id2, id3]).unwrap();

    //Encrypt
    let m = vec![29, 49, 47];
    let c = master_pub.encrypt(&[id1, id2, id3], m.clone()).unwrap();
    let cm = master_pub.encrypt::<Fr>(&[], m.clone()).unwrap();

    //Decrypt
    let dm = key3.decrypt(&c).unwrap();
    let dm_ = keyf.decrypt(&c).unwrap();
    let dmm = master_key.decrypt(&cm).unwrap();

    assert_eq!(m, dm);
    assert_eq!(m, dm_);
    assert_eq!(m, dmm);
}

#[test]
pub fn signature() {
    let mut rng = secp256k1::rand::rng();

    //Setup
    let master_key = MasterKey::new();
    let master_pub = master_key.master_pub();
    let id1 = get_scalar(&mut rng);
    let id2 = get_scalar(&mut rng);
    let id3 = get_scalar(&mut rng);

    //KeyGen
    let key1 = master_key.derive(&master_pub, &[id1]).unwrap();
    let key2 = key1.derive(&master_pub, &[id2]).unwrap();
    let key3 = key2.derive(&master_pub, &[id3]).unwrap();

    let keyf = master_key.derive(&master_pub, &[id1, id2, id3]).unwrap();

    //Encrypt
    let m = vec![29, 49, 47];
    let s2 = key2.sign(&master_pub, &m);
    let s3 = key3.sign(&master_pub, &[0, 39]);
    let sf = keyf.sign(&master_pub, &m);

    assert!(master_pub.verify(&[id1, id2], &s2, &m).is_ok());
    assert!(master_pub.verify(&[id1, id2, id3], &s3, &m).is_err());
    assert!(master_pub.verify(&[id1, id2, id3], &sf, &m).is_ok());
    assert!(master_pub.verify(&[id1, id2, id3], &sf, &[0, 39]).is_err());
    assert!(master_pub.verify(&[id1, id2, id3], &s3, &[0, 39]).is_ok());
}
