use bls12_381::{G1Projective, G1Affine, G2Projective, G2Affine, Gt, Scalar, Bls12};
use group::{Group, Curve};
use ff::Field;
use rand::{Rng, RngCore};
use std::ops::Neg;

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

//  // Define the public parameters structure
//  #[derive(Clone)]
//  pub struct PublicParams {
//      g: G1Projective, // Generator in G1
//      g2: G2Affine, // Generator in G2
//      x: G1Projective, // X = g^x in G1
//      y: G1Projective, // Y = g^y in G1 (adapted for asymmetric)
//      egg: Gt
//  }

//  // Define the master key structure
//  #[derive(Clone)]
//  pub struct MasterKey {
//      x: Scalar, // Master secret x ∈ Z_p^*
//      y: Scalar, // Master secret y ∈ Z_p^*
//  }

//  // Define the private key structure
//  #[derive(Clone, Debug)]
//  pub struct PrivateKey {
//      r: Scalar,       // Random r ∈ Z_p^*
//      k: G2Projective, // K = g2^{1/(ID + x + r·y)} ∈ G2
//  }

//  // Define the ciphertext structure
//  #[derive(Clone, Debug)]
//  pub struct Ciphertext {
//      a: G1Projective, // A = g^{s·ID} · X^s in G1
//      b: G1Projective, // B = Y^s in G1
//      c: Gt,           // C = e(g, g2)^s · M in GT
//  }

//  // Setup function as per Section 5.1 (adapted for asymmetric pairing)
//  pub fn setup() -> (PublicParams, MasterKey) {
//      let mut rng = rand::rng();

//      let g = G1Projective::generator();
//      let g2 = G2Affine::generator();

//      let x = get_scalar(&mut rng);
//      let y = get_scalar(&mut rng);

//      let x_point = g * x;
//      let y_point = g * y;

//      let egg = pairing(&g.to_affine(), &g2);

//      let params = PublicParams { g, g2, x: x_point, y: y_point, egg};
//      let master_key = MasterKey { x, y };

//      (params, master_key)
//  }

//  // KeyGen function as per Section 5.1 (K in G2)
//  pub fn keygen(master_key: &MasterKey, id: Scalar) -> PrivateKey {
//      let mut rng = rand::rng();

//      let r = get_scalar(&mut rng);

//      let r_y = r * master_key.y;
//      let denominator = id + master_key.x + r_y;

//      let k = G2Projective::generator() * denominator.invert().unwrap();

//      PrivateKey { r, k }
//  }

//  // Encrypt function as per Section 5.1 (adapted)
//  pub fn encrypt(params: &PublicParams, id: Scalar, message: Gt) -> Ciphertext {
//      let mut rng = rand::rng();

//      let s = get_scalar(&mut rng);

//      let s_id = s * id;
//      let g_s_id = params.g * s_id;
//      let x_s = params.x * s;
//      let a = g_s_id + x_s;

//      let b = params.y * s;

//      let e_g_g2_s = params.egg * s;

//      let c = e_g_g2_s + message;

//      Ciphertext { a, b, c }
//  }

//  // Decrypt function as per Section 5.1 (adapted for asymmetric)
//  pub fn decrypt(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Gt {
//      let b_r = ciphertext.b * private_key.r; // B^r in G1
//      let ab_r = ciphertext.a+b_r;
//      let ab_r_k = pairing(&ab_r.to_affine(), &private_key.k.to_affine());

//      ciphertext.c + -ab_r_k
//  }

//  // Test to show it works
//  #[cfg(test)]
//  mod tests {
//      use super::*;

//      #[test]
//      fn test_full_ibe() {
//          // Setup
//          let (params, master_key) = setup();

//          // Example identity and message
//          let mut rng = rand::rng();
//          let id = get_scalar(&mut rng);
//          let id2 = get_scalar(&mut rng);
//          let msg = get_scalar(&mut rng);
//          let message = Gt::generator() * msg;

//          // KeyGen
//          let private_key = keygen(&master_key, id);

//          // Encrypt
//          let ciphertext = encrypt(&params, id, message);

//          // Decrypt
//          let decrypted = decrypt(&private_key, &ciphertext);

//          // Verify
//          assert_eq!(message, decrypted, "Decryption should recover the original message");

//          println!("Full IBE test successful! Decrypted message matches original.");
//      }
//  }


//////////////////

    // Define the public parameters structure
  //#[derive(Clone)]
  //pub struct PublicParams {
  //    p: G1Projective,     // Generator in G1
  //    g1: G2Projective, // q ^ alpha in G2
  //    h: G2Projective,
  //}

  //// Define the master key structure
  //#[derive(Clone)]
  //pub struct MasterKey {
  //    g2a: G2Projective,       // Master secret alpha ∈ Z_p^*
  //}

  //// Define the private key structure
  //#[derive(Clone, Debug)]
  //pub struct PrivateKey {
  //    d0: G2Projective,   // d0 ∈ G2
  //    d: Vec<G1Projective>, // d1 to dj ∈ G1
  //}

  //// Define the ciphertext structure
  //#[derive(Clone, Debug)]
  //pub struct Ciphertext {
  //    a: Gt,               // A = egg ^ s · M in Gt
  //    b: G1Projective,     // B = p ^ s in G1
  //    c: Vec<G2Projective>,// C1 to Cj = Fk(Ik) ^ s in G2
  //}

  //// Setup function for HIBE with maximum depth l
  //pub fn setup() -> (PublicParams, MasterKey) {
  //    let mut rng = rand::thread_rng();

  //    let p = G1Projective::generator();
  //    let q = G2Projective::generator();

  //    let a = get_scalar(&mut rng);
  //    let g1 = q * a;
  //    let g2 = q * get_scalar(&mut rng);
  //    let g2a = g2 * a;

  //    let h = q*get_scalar(&mut rng);
  //  //let mut h_vec = Vec::with_capacity(max_depth);
  //  //for _ in 0..max_depth {
  //  //    let gamma = get_scalar(&mut rng);
  //  //    h_vec.push(q * gamma);
  //  //}

  //    //let egg = pairing(&p.to_affine(), &q_alpha.to_affine());

  //    let params = PublicParams {
  //        p,
  //        //q: q.to_affine(),
  //        g1,
  //        h,
  //    };
  //    let master_key = MasterKey { g2a };

  //    (params, master_key)
  //}

  //// KeyGen function: Generate private key for identity vector id: Vec<Scalar>
  //pub fn keygen(params: &PublicParams, master_key: &MasterKey, id: &[Scalar]) -> PrivateKey {
  //    let mut rng = rand::thread_rng();
  //    let j = id.len();

  //    let mut d0 = master_key.g2a;
  //    let mut d = Vec::with_capacity(j);

  //    for k in 0..j {
  //        let rk = get_scalar(&mut rng);
  //        let fk = (params.g1 * id[k]) + params.h;
  //        d0 = d0 + (fk * rk);
  //        d.push(params.p * rk);
  //    }

  //    PrivateKey { d0, d }
  //}

  //// Derive a child private key from a parent private key
  //pub fn derive_child(params: &PublicParams, parent_key: &PrivateKey, child_id_component: Scalar) -> PrivateKey {
  //    let mut rng = rand::thread_rng();
  //    let parent_depth = parent_key.d.len();

  //    let rk = get_scalar(&mut rng);
  //    let fk = params.g1 * child_id_component + params.h;
  //    let new_d0 = parent_key.d0 + (fk * rk);

  //    let mut new_d = parent_key.d.clone();
  //    new_d.push(params.p * rk);

  //    PrivateKey { d0: new_d0, d: new_d }
  //}

  //// Encrypt function
  //pub fn encrypt(params: &PublicParams, id: &[Scalar], message: Gt) -> Ciphertext {
  //    let mut rng = rand::thread_rng();
  //    let j = id.len();

  //    let s = get_scalar(&mut rng);

  //    let a = pairing(&params.p.to_affine(), &params.g1.to_affine()) * s + message;

  //    let b = params.p * s;

  //    let mut c = Vec::with_capacity(j);
  //    for k in 0..j {
  //        let fk = params.g1 * id[k] + params.h;
  //        c.push(fk * s);
  //    }

  //    Ciphertext { a, b, c }
  //}

  //// Decrypt function
  //pub fn decrypt(params: &PublicParams, private_key: &PrivateKey, ciphertext: &Ciphertext) -> Gt {
  //    let j = private_key.d.len();
  //    assert_eq!(j, ciphertext.c.len(), "Private key depth does not match ciphertext");

  //    let mut numerator = Gt::identity();
  //    for k in 0..j {
  //        let pair = pairing(&private_key.d[k].to_affine(), &ciphertext.c[k].to_affine());
  //        numerator = numerator + pair;
  //    }

  //    let denominator = pairing(&ciphertext.b.to_affine(), &private_key.d0.to_affine());

  //    ciphertext.a + numerator + denominator.neg()
  //}

  //// Test to show it works
  //#[cfg(test)]
  //mod tests {
  //    use super::*;

  //    #[test]
  //    fn test_full_hibe() {
  //        // Setup with max depth 3
  //        let (params, master_key) = setup();

  //        // Example identity at depth 2: id = (id1, id2)
  //        let mut rng = rand::thread_rng();
  //        let id1 = get_scalar(&mut rng);
  //        let id2 = get_scalar(&mut rng);
  //        let id3 = get_scalar(&mut rng);
  //        let id4 = get_scalar(&mut rng);
  //        let id = vec![id1, id2, id3];
  //        let idk = vec![id3, id4];

  //        // Random message
  //        let msg = get_scalar(&mut rng);
  //        let message = Gt::generator() * msg;

  //        // KeyGen for full id
  //        let private_key = keygen(&params, &master_key, &id);

  //        // Encrypt
  //        let ciphertext = encrypt(&params, &id, message);

  //        // Decrypt
  //        let decrypted = decrypt(&params, &private_key, &ciphertext);

  //        // Verify
  //        assert_eq!(message, decrypted, "Decryption should recover the original message");

  //        // Test hierarchical derivation
  //        // Generate key for prefix id1
  //        let prefix_id = vec![id1];
  //        let parent_key = keygen(&params, &master_key, &prefix_id);

  //        // Derive child key for id2
  //        let child_key = derive_child(&params, &parent_key, id2);
  //        let child_key = derive_child(&params, &child_key, id3);

  //        // Decrypt with derived key
  //        let decrypted_derived = decrypt(&params, &child_key, &ciphertext);

  //        assert_eq!(message, decrypted_derived, "Decryption with derived key should recover the original message");

  //        println!("Full HIBE test successful! Decrypted message matches original.");
  //    }
  //}
 

#[test]
fn main_test() {

  //let mut rng = rand::rng();

  //let g1 = G1Projective::generator();
  //let g2 = G2Projective::generator();
  //let gt = pairing(&g1, &g2);

  //let x = get_scalar(&mut rng);
  //let gtx = pairing(&(g1*x), &g2);
  //assert_eq!(gt*x, gtx);


    //Setup
    let mut rng = rand::rng();
    let a = get_scalar(&mut rng);
    let p = G1Projective::generator();
    let g = G2Projective::generator();
    let g1 = g*a;
    let pa = p*a;
    let h = vec![get_scalar(&mut rng), get_scalar(&mut rng), get_scalar(&mut rng)];

    let g2 = g*get_scalar(&mut rng);
    let master_key = g2*a;

    let F = |j: usize, x: Scalar| (g1*x) * h[j];

    //KeyGen
    let id = vec![get_scalar(&mut rng), get_scalar(&mut rng)];

    let r = vec![get_scalar(&mut rng), get_scalar(&mut rng)];

    let d_id = (master_key + ((F(0, id[0]) * r[0]) + (F(1, id[1]) * r[1])), vec![p*r[0], p*r[1]]);

    //Encrypt
    let M = Gt::generator()*get_scalar(&mut rng);
    let s = get_scalar(&mut rng);
    let egg = pairing(&pa, &g2);
    let A = (egg*s)+M;
    let B = p*s;
    let C = vec![F(0, id[0])*s, F(1, id[1])*s];

    //Decrypt
    let ecd = pairing(&d_id.1[0], &C[0]) + pairing(&d_id.1[1], &C[1]);

    let bd0 = pairing(&B, &d_id.0);
    let dm = A+(ecd + -bd0);
    assert_eq!(M, dm);
}
