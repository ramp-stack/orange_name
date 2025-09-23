use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::{Hash, Tag};
use std::array::TryFromSliceError;

use secp256k1::{SecretKey, PublicKey, Keypair};
use secp256k1::ellswift::{Party, ElligatorSwift};
use secp256k1::schnorr::Signature;
use secp256k1::rand;
use secp256k1::rand::Rng;

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key as ChaChaKey};

use bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, G2Prepared, Gt, Scalar, pairing};
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
    g1_h: G1Affine,
    egg: Gt
}

impl MasterPub {
    fn encrypt<R: Rng + ?Sized>(&self, rng: &mut R, id: &[Scalar], mut p: Vec<u8>) -> Vec<u8> {
        let ms = get_scalar(rng);
        let m = Gt::generator()*ms;

        let s = get_scalar(rng);
        let a = (self.egg*s)+m;

        let b = (G2Projective::generator()*s).to_affine();
        let c = (0..id.len()).map(|x| ((self.g1_h*id[x])*s).to_affine()).collect();
        let cipher = Cipher{a, b, c};

        let shared = HIBEHash::hash(&m.to_compressed());
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
    key: Key
}
impl MasterKey {
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let g2s = get_scalar(rng);
        let a = get_scalar(rng);
        let h = get_scalar(rng);

        let key = Key{
            d0: ((G1Projective::generator()*g2s)*a).to_affine(),
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
        let g1_h = (g1*self.h).to_affine();

        let g2 = g*self.g2s;
        let egg = pairing(&g2.to_affine(), &pa.to_affine());
        MasterPub{g1_h, egg}
    }

    pub fn to_key(self) -> Key {self.key}
}
impl Deref for MasterKey {type Target = Key; fn deref(&self) -> &Key {&self.key}}

pub struct Key {
    d0: G1Affine,
    dx: Vec<G2Prepared>
}
impl Key {
    fn derive<R: Rng + ?Sized>(&self, rng: &mut R, master_pub: &MasterPub, id: &[Scalar]) -> Key {
        let r = (0..id.len()).map(|_| get_scalar(rng)).collect::<Vec<_>>();
        let d0 = (0..id.len()).fold(self.d0, |key, x|
            (key + (master_pub.g1_h * id[x]) * r[x]).to_affine()
        );
        let dk = (0..id.len()).map(|x| G2Prepared::from((G2Projective::generator()*r[x]).to_affine())).collect();
        Key{d0, dx: [self.dx.clone(), dk].concat()}
    }

    fn decrypt(&self, p: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::from_slice(p)?;
        let cipher_size = cipher.size();
        let Cipher{a, b, c} = cipher;
        let ecd = bls12_381::multi_miller_loop(
            c.iter().zip(self.dx.iter()).collect::<Vec<_>>().as_slice()
        ).final_exponentiation();

        let bd0 = pairing(&self.d0, &b);
        let m = a+(ecd + -bd0);

        let shared = HIBEHash::hash(&m.to_compressed());
        let key = ChaChaKey::new(*shared.as_ref());

        let tag: [u8; 16] = p[cipher_size..cipher_size+16].try_into()?;
        let mut payload = p[cipher_size+16..].to_vec();

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None)?;
        Ok(payload)
    }
}

#[derive(Debug, PartialEq)]
struct Cipher {
    a: Gt,
    b: G2Affine,
    c: Vec<G1Affine>
}
impl Cipher {
    fn size(&self) -> usize {8+288+96+(self.c.len()*48)}

    fn to_vec(&self) -> Vec<u8> {
        [
            (self.c.len() as u64).to_be_bytes().to_vec(),
            self.a.to_compressed().to_vec(),
            self.b.to_compressed().to_vec(),
            self.c.iter().flat_map(|c| c.to_compressed().to_vec()).collect()
        ].concat()
    }

    fn from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        let c_len = u64::from_be_bytes(slice[0..8].try_into()?) as usize;
        Ok(Cipher{
            a: Gt::from_compressed(slice[8..8+288].try_into()?).unwrap(),
            b: G2Affine::from_compressed(slice[8+288..8+288+96].try_into()?).unwrap(),
            c: (0..c_len).map(|i| Ok(G1Affine::from_compressed(
                slice[8+288+96+(i*48)..8+288+96+(i*48)+48].try_into()?
            ).unwrap())).collect::<Result<_, TryFromSliceError>>()?
        })
    }
}

#[test]
pub fn encryption() {
    let mut rng = rand::rng();

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
