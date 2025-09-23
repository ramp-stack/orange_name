pub mod crypto;
//  use secp256k1::{SecretKey, PublicKey};
//  use secp256k1::schnorr::Signature as SchnorrSignature;
//  use std::str::FromStr;
//  use std::hash::Hash;
//  use std::fmt::Debug;

//  use serde::{Serialize, Deserialize};
//  use url::Url;

//  mod bls12_381;
//  use bls12_381::MasterKey;

//  mod secp256k1;
//  use secp256k1::{SecretKey, PublicKey};

//  type DateTime = chrono::DateTime<chrono::Utc>;

//  const ORANGEME_NAME: &str = "orange_name:03190689e2ecf319d31d34af8f5bb42dcc5b88d9cc482671b076285ce3a58ae318";
//  const ORANGEME_URI: &str = "air.orange.me:5702";

//  #[derive(Debug)]
//  pub enum Error {
//      Resolution(String),
//      Secp256k1(secp256k1::Error),
//      Bls12_381(bls12_381::Error),
//  }
//  impl std::error::Error for Error {}
//  impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}
//  impl From<secp256k1::Error> for Error {fn from(error: secp256k1::Error) -> Self {Error::Secp256k1(error)}}

//  #[derive(Clone, Copy, Debug, Hash, Ord, Eq, PartialOrd, PartialEq)]
//  #[derive(serde_with::SerializeDisplay)]
//  #[derive(serde_with::DeserializeFromStr)]
//  pub struct Name(PublicKey);
//  impl std::fmt::Display for Name {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//          write!(f, "orange_name:{}", self.0)
//      }
//  }
//  impl std::str::FromStr for Name {
//      type Err = secp256k1::Error;
//      fn from_str(s: &str) -> Result<Self, Self::Err> {
//          let split = s.split(":").collect::<Vec<_>>();
//          if split.len() != 2 || split[0] != "orange_name" {return Err(secp256k1::Error::InvalidPublicKey);}
//          Ok(Name(PublicKey::from_str(split[1])?))
//      }
//  }

//  #[derive(Serialize, Deserialize, PartialOrd, PartialEq, Debug, Clone, Hash, Ord, Eq)]
//  pub struct Endpoint(pub OrangeName, pub Url);

//  #[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Debug, Hash, Ord, Eq)]
//  pub enum Signature {
//      Secp256k1(secp256k1::Signature),
//      Bls12_381(bls12_381::SecretKey)
//  }
//  impl Signature {}

//  #[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Eq)]
//  pub enum Secret {
//      Secp256k1(SecretKey),
//      Bls12_381(Name, Vec<String>, Key)
//  }
//  impl Secret {
//      pub fn new() -> Self {}

//      pub fn name(&self) -> Name {match self {
//          Self::Secp256k1(key) => Name(key.easy_public_key())
//          Self::Bls12_381(name, _) => *name
//      }}

//      pub fn sign(&self, path: &[&str], payload: &[u8]) -> Result<Signature, Error> {match self {
//          Self::Secp256k1(key) => Signature::Secp256k1(key.sign(payload))
//      }}

//      pub fn decrypt(&self, path: &[&str], payload: &[u8]) -> Result<Vec<u8>, Error> {match self {
//          Self::Secp256k1(key) => Signature::Secp256k1(key.decrypt(payload))
//      }}
//  }
//  impl Default for Secret {fn default() -> Self {
//      Self::Temporary(SecretKey::new(&mut rand::rng()))
//  }}



//  #[derive(Default, Debug)]
//  pub struct OrangeResolver;
//  impl OrangeResolver {
//      

//      pub async fn verify(&mut self, name: &OrangeName, sig: &OrangeSignature, payload: &[u8], _when: Option<DateTime>) -> Result<(), Error> {
//          match sig {
//              OrangeSignature::Temporary(sig) => name.0.easy_verify(sig, payload)?
//          }
//          Ok(())
//      }
//      
//      pub async fn lookup(&mut self, _name: &OrangeName, tag: Option<&str>, _when: Option<DateTime>) -> Result<Vec<(String, Endpoint)>, Error> {
//          match tag {
//              Some(tag) if tag != "default" => Ok(Vec::new()),
//              _ => Ok(vec![("default".to_string(), Endpoint(
//                  OrangeName::from_str(ORANGEME_NAME).unwrap(),
//                  Url::from_str(ORANGEME_URI).unwrap()
//              ))]),
//          }
//      }
//  }

//  //  #[derive(Serialize, Deserialize, Clone, Debug, Hash)]
//  //  pub struct Signed<T>(OrangeName, OrangeSignature, T);
//  //  impl<T: Hash + Serialize + for<'a> Deserialize<'a> + Clone + Debug> Signed<T> {
//  //      pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, inner: T) -> Result<Self, Error> {
//  //          let signature = resolver.sign(secret, EasyHash::core_hash(&inner).as_ref()).await?;
//  //          Ok(Signed(secret.name(), signature, inner))
//  //      }
//  //      pub fn into_inner(self) -> T {self.2}
//  //      pub fn signer(&self) -> &OrangeName {&self.0}
//  //      pub async fn verify(&self, resolver: &mut OrangeResolver, when: Option<DateTime>) -> Result<OrangeName, Error> {
//  //          resolver.verify(&self.0, &self.1, EasyHash::core_hash(&self.2).as_ref(), when).await?;
//  //          Ok(self.0.clone())
//  //      }
//  //  }
//  //  impl<T: Hash + Serialize + for<'a> Deserialize<'a> + Clone + Debug> AsRef<T> for Signed<T> {fn as_ref(&self) -> &T {&self.2}}
