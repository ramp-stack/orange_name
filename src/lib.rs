use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::{Hash, Tag};

use serde::{Serialize, Deserialize};

use std::str::FromStr;

use chrono::Utc;

mod secp256k1;
//mod bls12_381;

type DateTime = chrono::DateTime<Utc>;

const ORANGEME_NAME: &str = "orange_name:03190689e2ecf319d31d34af8f5bb42dcc5b88d9cc482671b076285ce3a58ae318";
const ORANGEME_URI: &str = "air.orange.me:5702";

#[derive(Debug)]
pub enum Error {
    Secp256k1(secp256k1::Error),
    //Bls12_381(bls12_381::Error),
    SerdeJson(serde_json::Error),
    MissingPermissions(Vec<Id>),
    MissingTag(String),
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}
impl From<secp256k1::Error> for Error {fn from(e: secp256k1::Error) -> Self {Error::Secp256k1(e)}}
//impl From<bls12_381::Error> for Error {fn from(e: bls12_381::Error) -> Self {Error::Bls12_381(e)}}
impl From<serde_json::Error> for Error {fn from(e: serde_json::Error) -> Self {Error::SerdeJson(e)}}
impl Error {fn missing(t: &str) -> Error {Error::MissingTag(t.to_string())}}

const MIDSTATE: Midstate = Midstate::hash_tag(b"ORANGE_NAME");
const HARDEND: [u8; 11] = *b"hardend key";

struct OrangeTag;
impl Tag for OrangeTag {fn engine() -> HashEngine {HashEngine::from_midstate(MIDSTATE)}}
type OrangeHash = Hash<OrangeTag>;

#[derive(Default)]
struct HashReader(Vec<u8>);
impl core::hash::Hasher for HashReader {
    fn finish(&self) -> u64 {panic!("NOOP");}
    fn write(&mut self, bytes: &[u8]) {self.0.extend(bytes);}
}
impl HashReader {
    pub fn read<H: std::hash::Hash>(h: &H) -> Vec<u8> {
        let mut hasher = HashReader::default();
        h.hash(&mut hasher);
        hasher.0
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Id([u8; 32]);
impl AsRef<[u8]> for Id {fn as_ref(&self) -> &[u8] {&self.0}}
impl std::ops::Deref for Id {type Target = [u8; 32]; fn deref(&self) -> &Self::Target {&self.0}}
impl std::ops::DerefMut for Id {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl From<[u8; 32]> for Id {fn from(id: [u8; 32]) -> Self {Id(id)}}
impl Id {
    pub const MAX: Id = Id([u8::MAX; 32]);
    pub const MIN: Id = Id([u8::MIN; 32]);
    pub fn hash<H: std::hash::Hash>(h: &H) -> Self {
        Id(*OrangeHash::hash(&HashReader::read(h)).as_ref())
    }
    pub fn random() -> Self {Id(secp256k1::rand::random())}
}
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::str::FromStr for Id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Id(hex::decode(s)?.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)?))
    }
}

#[derive(Clone, Copy, Debug, Hash, Ord, Eq, PartialOrd, PartialEq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Name(secp256k1::PublicKey);
impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "orange_name:{}", self.0)
    }
}
impl std::str::FromStr for Name {
    type Err = secp256k1::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(":").collect::<Vec<_>>();
        if split.len() != 2 || split[0] != "orange_name" {return Err(secp256k1::Error::InvalidPublicKey);}
        Ok(Name(secp256k1::PublicKey::from_str(split[1])?))
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    name: Name,
    path: Vec<Id>,
    temporary: secp256k1::SecretKey,
    //secrets: Vec<(DateTime, (secp256k1::SecretKey, bls12_381::SecretKey, bls12_381::MasterPub))>
}
impl Secret {
    pub fn new() -> Self {
        let temporary = secp256k1::SecretKey::new();
        Secret{name: Name(temporary.public_key()), path: vec![], temporary}
    }
    pub fn name(&self) -> Name {self.name}
    //pub fn is_temporary(&self) -> bool {self.secrets.is_empty()}
    pub fn sign(&self, path: &[Id], payload: &[u8]) -> Result<Signature, Error> {
        let _path = path.strip_prefix(self.path.as_slice()).ok_or(Error::MissingPermissions(path.to_vec()))?;
        Ok(Signature::Secp256k1(self.temporary.sign(payload)))
    }

    pub fn decrypt(&self, _datetime: &DateTime, path: &[Id], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let _path = path.strip_prefix(self.path.as_slice()).ok_or(Error::MissingPermissions(path.to_vec()))?;
        Ok(self.temporary.decrypt(payload)?)
    }

    pub fn get_hardend(&self, _datetime: &DateTime, path: &[Id]) -> Result<secp256k1::SecretKey, Error> {
        let path = path.strip_prefix(self.path.as_slice()).ok_or(Error::MissingPermissions(path.to_vec()))?;
        Ok(self.temporary.derive(path).derive(&[HARDEND]))
    }

    pub fn derive(&self, path: &[Id]) -> Result<Self, Error> {
        let _path = path.strip_prefix(self.path.as_slice()).ok_or(Error::MissingPermissions(path.to_vec()))?;
        Ok(self.clone())
      //let mut secret = self.clone();
      //if self.is_temporary() {return Ok(secret);}
      //secret.secrets.iter_mut().for_each(|(_, sb)| {
      //    *sb = (sb.0.derive(path), sb.1.derive(&sb.2, path)?, sb.2);
      //});
      //Ok(secret)
    }

  //fn choose_by_date(&self, datetime: &DateTime) -> Vec<(secp256k1::SecretKey, Option<bls12_381::SecretKey>)> {
  //  ////Return the oldest secret that is less than the datetime (valid at the time)
  //  //self.secrets.iter().find(|(d, sb)| d < datetime);
  //  ////Return any secrets that were created in the 24 hours before datetime(within the roll window)
  //  //self.secrets.iter().filter(|(d, sb)| d < datetime && *d > (datetime-Duration::from_hours(24)));
  //  ////If the first secret is within 24 hours of the requested date include temporary key
  //  //if self.secrets.last().map(|(d, sb)| 
  //  ////If the first two predicates returned nothing return the temporary key
  //}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Secp256k1(secp256k1::Signature),
    //Bls12_381(bls12_381::Signature),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Public {
    Secp256k1(secp256k1::PublicKey),
    //Bls12_381(bls12_381::MasterPub)
}
impl Public {
    pub fn verify(&mut self, _path: &[Id], sig: &Signature, payload: &[u8]) -> Result<(), Error> {
        match (self, sig) {
            (Self::Secp256k1(key), Signature::Secp256k1(sig)) => key.verify(sig, payload)?,
          //(Self::Bls12_381(master), Signature::Bls12_381(sig)) => {
          //    master.verify(&path, sig, payload)?
          //},
            //_ => Err(secp256k1::Error::InvalidSignature)?
        };
        Ok(())
    }

    pub fn encrypt(&mut self, _path: &[Id], payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Self::Secp256k1(key) => key.encrypt(payload)?,
          //Self::Bls12_381(master) => {
          //    master.encrypt(&path, payload)?
          //}
        })
    }
}

#[derive(Default, Debug)]
pub struct Resolver;
impl Resolver {
    pub async fn verify(&mut self, name: &Name, datetime: &DateTime, path: &[Id], sig: &Signature, payload: &[u8]) -> Result<(), Error> {
        serde_json::from_str::<Public>(
            &self.lookup(name, datetime, "public").await?.ok_or(Error::missing("public"))?
        )?.verify(path, sig, payload)
    }

    pub async fn encrypt(&mut self, name: &Name, path: &[Id], payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        serde_json::from_str::<Public>(
            &self.lookup(name, &Utc::now(), "public").await?.ok_or(Error::missing("public"))?
        )?.encrypt(path, payload)
    }
    
    pub async fn lookup(&mut self, name: &Name, _datetime: &DateTime, tag: &str) -> Result<Option<String>, Error> {
        Ok(match tag {
            "air_uri" if name == &Name::from_str(ORANGEME_NAME).unwrap() =>
                Some(ORANGEME_URI.to_string()),
            "air_names" => Some([ORANGEME_NAME].join(",")),
            "public" => Some(serde_json::to_string(&Public::Secp256k1(name.0)).unwrap()),
            _ => None
        })
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};
    use std::thread::{self, Thread};
    use core::pin::pin;

    /// A waker that wakes up the current thread when called.
    struct ThreadWaker(Thread);

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    /// Run a future to completion on the current thread.
    fn block_on<T>(fut: impl Future<Output = T>) -> T {
        // Pin the future so it can be polled.
        let mut fut = pin!(fut);

        // Create a new context to be passed to the future.
        let t = thread::current();
        let waker = Arc::new(ThreadWaker(t)).into();
        let mut cx = Context::from_waker(&waker);

        // Run the future to completion.
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(res) => return res,
                Poll::Pending => thread::park(),
            }
        }
    }

    #[test]
    pub fn encryption() {
        let secret = Secret::new();
        let name = secret.name();

        let id = Id::random();

        let m = vec![1, 2, 3];
        let c = block_on(Resolver.encrypt(&name, &[id], m.clone())).unwrap();
        assert_eq!(m, secret.decrypt(&Utc::now(), &[id], &c).unwrap())
    }

    #[test]
    pub fn signature() {
        let secret = Secret::new();
        let name = secret.name();

        let id = Id::random();

        let m = vec![1, 2, 3];
        let s = secret.sign(&[id], &m).unwrap();
        block_on(Resolver.verify(&name, &Utc::now(), &[id], &s, &m)).unwrap();
    }
}


