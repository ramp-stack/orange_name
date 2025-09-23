use std::str::FromStr;
use std::hash::Hash;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};
use url::Url;

mod bls12_381;
//use bls12_381::{MasterKey, MasterPub, Key};

mod secp256k1;
use secp256k1::{SecretKey, PublicKey};


//  #[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Debug, Hash, Ord, Eq)]
//  pub enum Signature {
//      Secp256k1(secp256k1::Signature),
//      Bls12_381(bls12_381::SecretKey)
//  }
//  impl Signature {}

//  #[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Eq)]
//  pub enum Secret {
//      Secp256k1(SecretKey),
//      Bls12_381(Vec<String>, Key)
//  }
//  impl Secret {
//      pub fn secp256k1<R: Rng + ?Sized>(rng: &mut R) -> Self {
//          Self::Secp256k1(SecretKey::new(rng))
//      }
//      pub fn bls12_381<R: Rng + ?Sized>(rng: &mut R) -> (Self, MasterPub) {
//          let master = MasterKey::new(rng);
//          (Self::Bls12_381(vec![], master.to_key()), master.master_pub())
//      }
//      pub fn sign(&self, path: &[&str], payload: &[u8]) -> Result<Signature, Error> {match self {
//          Self::Secp256k1(key) => Signature::Secp256k1(key.sign(payload))
//      }}

//      pub fn decrypt(&self, path: &[&str], payload: &[u8]) -> Result<Vec<u8>, Error> {match self {
//          Self::Secp256k1(key) => Signature::Secp256k1(key.decrypt(payload))
//      }}
//  }
