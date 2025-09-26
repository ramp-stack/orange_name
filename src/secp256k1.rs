use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, SECP256K1};
use secp256k1::ellswift::{Party, ElligatorSwift};

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key};
use serde::{Serialize, Deserialize};

use crate::OrangeHash;

use std::str::FromStr;

pub use secp256k1::{rand, Error};

const DATA: &str = "easy_secp256k1_ellswift_xonly_ecdh";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signature(SchnorrSignature);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct PublicKey(secp256k1::PublicKey);
impl PublicKey {
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        signature.0.verify(
            OrangeHash::hash(payload).as_ref(),
            &self.0.x_only_public_key().0
        )
    }

    pub fn from_str(p: &str) -> Result<Self, Error> {
        Ok(PublicKey(secp256k1::PublicKey::from_str(p)?))
    }

    pub fn encrypt(&self, mut payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        let secret = SecretKey::new();
        let mine = ElligatorSwift::from_pubkey(secret.public_key().0);
        let theirs = ElligatorSwift::from_pubkey(self.0);
        let ecdh_sk = ElligatorSwift::shared_secret(mine, theirs, secret.0, Party::Initiator, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());
        Ok([
            mine.to_array().to_vec(),//TODO: unencrypted
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut payload, None).to_vec(),
            payload
        ].concat())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        Ok(PublicKey(secp256k1::PublicKey::from_str(s)?))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey(secp256k1::SecretKey);
impl SecretKey {
    pub fn new() -> Self {
        SecretKey(secp256k1::SecretKey::new(&mut secp256k1::rand::rng()))
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key(SECP256K1))
    }

    pub fn sign(&self, payload: &[u8]) -> Signature {
        let keypair = Keypair::from_secret_key(SECP256K1, &self.0);
        Signature(SECP256K1.sign_schnorr(OrangeHash::hash(payload).as_ref(), &keypair))
    }

    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() < 64+16 {return Err(Error::InvalidMessage);}
        let theirs = ElligatorSwift::from_array(payload[0..64].try_into().or(Err(Error::InvalidMessage))?);
        let tag: [u8; 16] = payload[64..64+16].try_into().or(Err(Error::InvalidMessage))?;
        let mut payload = payload[64+16..].to_vec();

        let mine = ElligatorSwift::from_pubkey(self.public_key().0);
        let ecdh_sk = ElligatorSwift::shared_secret(theirs, mine, self.0, Party::Responder, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None).map_err(|_| Error::InvalidMessage)?;
        Ok(payload)
    }

    /// Hashes the current key with the path item, (key, path) = child_key
    /// /1020/0/234 is not the same as /1020/0234
    pub fn derive<H: std::hash::Hash>(&self, path: &[H]) -> Self {
        let mut key = self.0;
        for p in path {
            let bytes = crate::HashReader::read(p);
            key = secp256k1::SecretKey::from_byte_array(
                *OrangeHash::hash(&[&key.secret_bytes() as &[u8], &bytes].concat()).as_ref()
            ).unwrap();
        }
        SecretKey(key)
    }
}

#[test]
fn signature() {
    let secret_key = SecretKey::new();
    let message = b"my message";
    let signature = secret_key.sign(message);

    let public_key = secret_key.public_key();
    public_key.verify(&signature, message).unwrap();
}

#[test]
fn encryption() {
    let secret_key = SecretKey::new();
    let public_key = secret_key.public_key();

    let message = b"my message".to_vec();
    let payload = public_key.encrypt(message.clone()).unwrap();

    assert_eq!(message, secret_key.decrypt(&payload).unwrap());
}
