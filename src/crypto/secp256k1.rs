use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::Hash;
use bitcoin_hashes::sha256t::Tag;

use secp256k1::{Keypair, Signing, Secp256k1};
pub use secp256k1::{SecretKey, PublicKey};
use secp256k1::ellswift::{Party, ElligatorSwift};
pub use secp256k1::schnorr::Signature;
use secp256k1::rand;
use secp256k1::rand::Rng;

use bitcoin::bip32::{ChildNumber, ChainCode, Xpriv};

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key};

pub use secp256k1::Error;

//  mod signed;
//  pub use signed::Signed;

const MIDSTATE: Midstate = Midstate::hash_tag(b"SECP256K1_EASY");
const DATA: &str = "easy_secp256k1_ellswift_xonly_ecdh";

struct HashReader(Vec<u8>);
impl core::hash::Hasher for HashReader {
    fn finish(&self) -> u64 {panic!("NOOP");}
    fn write(&mut self, bytes: &[u8]) {self.0.extend(bytes);}
}

pub struct EasyTag;
impl Tag for EasyTag {
    fn engine() -> HashEngine {HashEngine::from_midstate(MIDSTATE)}
}
///Tagged Sha256 Hasher
pub type EasyHash = Hash<EasyTag>;

pub trait Hashable {
    fn core_hash<H: core::hash::Hash>(hashable: &H) -> Self where Self: Sized;
}

impl Hashable for EasyHash {
   fn core_hash<H: core::hash::Hash>(hashable: &H) -> Self {
        let mut reader = HashReader(Vec::new());
        hashable.hash(&mut reader);
        EasyHash::hash(&reader.0)
   }
}

pub trait EasyPublicKey {
    fn verify_schnorr(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error>;
    fn encrypt<R: Rng + ?Sized, C: Signing>(
        &self, rng: &mut R, secp: &Secp256k1<C>, payload: Vec<u8>
    ) -> Result<Vec<u8>, Error>;
}
impl EasyPublicKey for PublicKey {
    fn verify_schnorr(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        signature.verify(
            EasyHash::hash(payload).as_ref(),
            &self.x_only_public_key().0
        )
    }

    fn encrypt<R: Rng + ?Sized, C: Signing>(
        &self, rng: &mut R, secp: &Secp256k1<C>, mut payload: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let secret = SecretKey::new(rng);
        let mine = ElligatorSwift::from_pubkey(secret.public_key(secp));
        let theirs = ElligatorSwift::from_pubkey(*self);
        let ecdh_sk = ElligatorSwift::shared_secret(mine, theirs, secret, Party::Initiator, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());
        Ok([
            mine.to_array().to_vec(),//TODO: unencrypted
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut payload, None).to_vec(),
            payload
        ].concat())
    }
}

pub trait EasySecretKey {
    fn sign<C: Signing>(&self, secp: &Secp256k1<C>, payload: &[u8]) -> Signature;
    fn decrypt<C: Signing>(&self, secp: &Secp256k1<C>, payload: &[u8]) -> Result<Vec<u8>, Error> ;
    fn derive(&self, path: &[u32]) -> Result<Self, Error> where Self: Sized;
}

impl EasySecretKey for SecretKey {
    fn sign<C: Signing>(&self, secp: &Secp256k1<C>, payload: &[u8]) -> Signature {
        let keypair = Keypair::from_secret_key(secp, self);
        secp.sign_schnorr(EasyHash::hash(payload).as_ref(), &keypair)
    }

    fn decrypt<C: Signing>(&self, secp: &Secp256k1<C>, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() < 64+16 {return Err(Error::InvalidMessage);}
        let theirs = ElligatorSwift::from_array(payload[0..64].try_into().or(Err(Error::InvalidMessage))?);
        let tag: [u8; 16] = payload[64..64+16].try_into().or(Err(Error::InvalidMessage))?;
        let mut payload = payload[64+16..].to_vec();

        let mine = ElligatorSwift::from_pubkey(self.public_key(secp));
        let ecdh_sk = ElligatorSwift::shared_secret(theirs, mine, *self, Party::Responder, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None).map_err(|_| Error::InvalidMessage)?;
        Ok(payload)
    }

    fn derive(&self, path: &[u32]) -> Result<Self, Error> {
        let x_priv = Xpriv{
            network: bitcoin::Network::Bitcoin.into(),
            depth: 0,
            parent_fingerprint: [0; 4].into(),
            child_number: ChildNumber::from_hardened_idx(0).unwrap(),
            private_key: bitcoin::secp256k1::SecretKey::from_slice(&self.secret_bytes()).unwrap(),
            chain_code: ChainCode::from(self.secret_bytes())
        };
        let path = path.iter().map(|i|
            ChildNumber::from_hardened_idx(*i).map_err(|_| Error::InvalidSecretKey)
        ).collect::<Result<Vec<_>, Error>>()?;
        let r_priv = x_priv.derive_priv(&bitcoin::key::Secp256k1::new(), &path).unwrap().to_priv().inner;
        Ok(SecretKey::from_byte_array(r_priv.secret_bytes()).unwrap())
    }
}

#[test]
fn signature() {
    let mut rng = rand::rng();
    let secp = Secp256k1::new();

    let secret_key = SecretKey::new(&mut rng);
    let message = b"my message";
    let signature = secret_key.sign(&secp, message);

    let public_key = secret_key.public_key(&secp);
    public_key.verify_schnorr(&signature, message).unwrap();
}

#[test]
fn encryption() {
    let mut rng = rand::rng();
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rng);
    let public_key = secret_key.public_key(&secp);

    let message = b"my message".to_vec();
    let payload = public_key.encrypt(&mut rng, &secp, message.clone()).unwrap();

    assert_eq!(message, secret_key.decrypt(&secp, &payload).unwrap());
}
