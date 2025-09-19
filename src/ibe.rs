use bls12_381::{G1Projective, G2Projective, Gt, Scalar};
use group::{Group, Curve};
use rand::{Rng};

fn pairing(g1: &G1Projective, g2: &G2Projective) -> Gt {
    bls12_381::pairing(&g1.to_affine(), &g2.to_affine())
}

fn get_scalar(rng: &mut impl Rng) -> Scalar {
    loop {
        if let Some(x) = Scalar::from_bytes(&rng.random::<[u8; 32]>()).into_option() {
            break x;
        }
    }
}

struct Params {
    p: G1Projective,
    h: G2Projective,
    egg: Gt
}

type MasterKey = G2Projective;

fn setup() -> (Params, MasterKey) {
    let mut rng = rand::rng();
    let a = get_scalar(&mut rng);
    let p = G1Projective::generator();
    let g = G2Projective::generator();
    let g1 = g*a;
    let pa = p*a;
    let h = g1*get_scalar(&mut rng);

    let g2 = g*get_scalar(&mut rng);
    let master_key = g2*a;

    let egg = pairing(&pa, &g2);
    (Params{p, h, egg}, master_key)
}

type Key = (G2Projective, Vec<G1Projective>);

//(MasterKey, vec![]) for root

fn keygen(params: &Params, key: &Key, id: &[Scalar]) -> Key {
    let mut rng = rand::rng();
    let r = (0..id.len()).map(|_| get_scalar(&mut rng)).collect::<Vec<_>>();
    let d0 = (0..id.len()).fold(key.0.clone(), |key, x| key + (params.h * id[x]) * r[x]);
    let dk = (0..id.len()).map(|x| params.p*r[x]).collect();
    (d0, [key.1.clone(), dk].concat())
}

type C = (Gt, G1Projective, Vec<G2Projective>);

fn encrypt(params: &Params, id: &[Scalar], m: Gt) -> C {
    let mut rng = rand::rng();
    let s = get_scalar(&mut rng);
    let a = (params.egg*s)+m;
    let b = params.p*s;
    let c = (0..id.len()).map(|x| (params.h*id[x])*s).collect();
    (a, b, c)
}

fn decrypt(key: &Key, c: &C) -> Gt {
    let (a, b, c) = c;
    let ecd = c.iter().enumerate().fold(Gt::identity(), |gt, (x, cx)|
        gt + pairing(&key.1[x], &cx)
    );

    let bd0 = pairing(&b, &key.0);
    a+(ecd + -bd0)
}

pub fn main_test2() {
    let mut rng = rand::rng();


    //Setup
    let (params, key) = setup();
    let id1 = get_scalar(&mut rng);
    let id2 = get_scalar(&mut rng);
    let id3 = get_scalar(&mut rng);

    //KeyGen
    let key1 = keygen(&params, &(key, vec![]), &[id1]);
    let key2 = keygen(&params, &key1, &[id2]);
    let key3 = keygen(&params, &key2, &[id3]);

    let keyf = keygen(&params, &(key, vec![]), &[id1, id2, id3]);

    //Encrypt
    let m = Gt::generator()*get_scalar(&mut rng);
    let c = encrypt(&params, &[id1, id2, id3], m);

    //Decrypt
    let dm = decrypt(&key3, &c);
    let dm_ = decrypt(&keyf, &c);

    assert_eq!(m, dm);
    assert_eq!(m, dm_);
}


#[test]
fn testt() {
    main_test2();
}
