use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::{Hash, Tag};
use std::array::TryFromSliceError;

use secp256k1::{SECP256K1, SecretKey, PublicKey, Keypair};
use secp256k1::ellswift::{Party, ElligatorSwift};
use secp256k1::schnorr::Signature;
use secp256k1::rand;
use secp256k1::rand::Rng;

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key as ChaChaKey};

use bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, Gt, Scalar, pairing};
use group::{Group, Curve, GroupEncoding};
use std::ops::Deref;

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

fn get_scalar<R: Rng + ?Sized>(rng: &mut R) -> Scalar {loop {
    if let Some(x) = Scalar::from_bytes(&rng.random::<[u8; 32]>()).into_option() {
        break x;
    }
}}

#[derive(Clone, Copy, Debug)]
pub struct MasterPub {
    p: G1Affine,
    g1_h: G2Affine,
    egg: Gt
}

impl MasterPub {
    fn encrypt<R: Rng + ?Sized>(&self, rng: &mut R, id: &[Scalar], mut p: Vec<u8>) -> Vec<u8> {
        let ms = get_scalar(rng);
        let m = Gt::generator()*ms;

        let s = get_scalar(rng);
        let a = (self.egg*s)+m;
        let b = (self.p*s).to_affine();
        let c = (0..id.len()).map(|x| ((self.g1_h*id[x])*s).to_affine()).collect();
        let cipher = Cipher{a, b, c};

        let shared = HIBEHash::hash(&m.to_byte_array());
        let key = ChaChaKey::new(*shared.as_ref());
        [
            cipher.to_vec(),
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut p, None).to_vec(),
            p
        ].concat()
    }
}

pub struct MasterKey{
    h: Scalar,
    g2s: Scalar,
    a: Scalar,
    key: Key,
    master_pub: MasterPub
}
impl MasterKey {
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let g2s = get_scalar(rng);
        let a = get_scalar(rng);
        let h = get_scalar(rng);

        //Precompute MasterPub
        let p = G1Projective::generator();
        let g = G2Projective::generator();
        let g1 = g*a;
        let pa = p*a;
        let g1_h = (g1*h).to_affine();

        let g2 = g*g2s;
        let egg = pairing(&pa.to_affine(), &g2.to_affine());

        MasterKey{
            h, g2s, a,
            key: Key{
                d0: ((G2Projective::generator()*g2s)*a).to_affine(),
                dx: vec![]
            },
            master_pub: MasterPub{p: p.to_affine(), g1_h, egg}
        }
    } 

    pub fn master_pub(&self) -> &MasterPub {&self.master_pub }
}
impl Deref for MasterKey {type Target = Key; fn deref(&self) -> &Key {&self.key}}

pub struct Key {
    d0: G2Affine,
    dx: Vec<G1Affine>
}
impl Key {
    fn derive<R: Rng + ?Sized>(&self, rng: &mut R, master_pub: &MasterPub, id: &[Scalar]) -> Key {
        let r = (0..id.len()).map(|_| get_scalar(rng)).collect::<Vec<_>>();
        let d0 = (0..id.len()).fold(self.d0, |key, x|
            (key + (master_pub.g1_h * id[x]) * r[x]).to_affine()
        );
        let dk = (0..id.len()).map(|x| (master_pub.p*r[x]).to_affine()).collect();
        Key{d0, dx: [self.dx.clone(), dk].concat()}
    }

    fn decrypt(&self, p: &[u8]) -> Result<Vec<u8>, Error> {
        let Cipher{a, b, c} = Cipher::from_slice(p)?;
        let ecd = c.iter().enumerate().fold(Gt::identity(), |gt, (x, cx)|
            gt + pairing(&self.dx[x], cx)
        );

        let bd0 = pairing(&b, &self.d0);
        let m = a+(ecd + -bd0);

        let shared = HIBEHash::hash(&m.to_byte_array());
        let key = ChaChaKey::new(*shared.as_ref());

        let cipher_size = 8+576+48+(c.len()*96);
        let tag: [u8; 16] = p[cipher_size..cipher_size+16].try_into()?;
        let mut payload = p[cipher_size+16..].to_vec();

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None)?;
        Ok(payload)
    }
}

#[derive(Debug, PartialEq)]
pub struct Cipher {
    a: Gt,
    b: G1Affine,
    c: Vec<G2Affine>
}
impl Cipher {
    ///Vector is 8+576+48+(id_depth*96)
    fn to_vec(&self) -> Vec<u8> {
        [
            (self.c.len() as u64).to_be_bytes().to_vec(),
            self.a.to_byte_array().to_vec(),
            self.b.to_compressed().to_vec(),
            self.c.iter().flat_map(|c| c.to_compressed().to_vec()).collect()
        ].concat()
    }

    fn from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        let c_len = u64::from_be_bytes(slice[0..8].try_into()?) as usize;
        Ok(Cipher{
            a: Gt::from_byte_array(slice[8..8+576].try_into()?),
            b: G1Affine::from_compressed(slice[8+576..8+576+48].try_into()?).unwrap(),
            c: (0..c_len).map(|i| Ok(G2Affine::from_compressed(
                slice[8+576+48+(i*96)..8+576+48+(i*96)+96].try_into()?
            ).unwrap())).collect::<Result<_, TryFromSliceError>>()?
        })
    }
}

#[test]
pub fn main_test2() {
    let mut rng = rand::rng();

    //Setup
    let master_key = MasterKey::new(&mut rng);
    let master_pub = *master_key.master_pub();
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

    //Decrypt
    let dm = key3.decrypt(&c).unwrap();
    let dm_ = keyf.decrypt(&c).unwrap();

    assert_eq!(m, dm);
    assert_eq!(m, dm_);
}
