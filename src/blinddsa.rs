// Blind Signature for ED-DSE using ristretto

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use sha3::{Digest, Sha3_512};


// generating a base point, and another point for ElGamal
pub fn crs_gen()
        -> (RistrettoPoint, RistrettoPoint){
    println!("Generating a pair of group elements");
    let mut rng = OsRng::new().unwrap();
    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);

    (g,h)

}

pub fn hashp2_to_scal(p: RistrettoPoint, p2: RistrettoPoint)
        -> Scalar{
    // Returns a Scalar corresponding to the hash of the first three coordinates
    let mut has = Sha3_512::new();
    has.input(p.compress().to_bytes());
    has.input(p2.compress().to_bytes());

    Scalar::from_hash(has)
}
pub fn prove2(k2: Scalar, g: RistrettoPoint, r2: RistrettoPoint)
        -> (RistrettoPoint, Scalar){
    let mut rng = OsRng::new().unwrap();
    let kp = Scalar::random(&mut rng);
    let prg = kp*g;
    let e = hashp2_to_scal(r2,prg);
    (prg, k2 * e + kp)
}

pub fn verproof2(pr2:(RistrettoPoint,Scalar), r2:RistrettoPoint,g:RistrettoPoint)
        -> bool {
    let e = hashp2_to_scal(r2,pr2.0);

    e*r2 + pr2.0 == pr2.1 * g

}

// Key initialization
pub fn key_init(g: RistrettoPoint)
        -> (Scalar,(RistrettoPoint,(RistrettoPoint,Scalar))) {
    let mut rng = OsRng::new().unwrap();
    let sk = Scalar::random(&mut rng);
    let pk = sk * g;
    let pr = prove2(sk,g, pk);


    (sk,(pk,pr))
}


// Interactive Blind Signing

pub fn hashp3_to_scal(p: RistrettoPoint, p2: RistrettoPoint, p3: RistrettoPoint, p4: RistrettoPoint)
        -> Scalar {
    // Returns a Scalar corresponding to the hash of the first 4 coordinates
    let mut has = Sha3_512::new();
    has.input(p.compress().to_bytes());
    has.input(p2.compress().to_bytes());
    has.input(p3.compress().to_bytes());
    has.input(p4.compress().to_bytes());

    Scalar::from_hash(has)
}


pub fn hashp_to_scal(p: RistrettoPoint)
        ->Scalar {
    // Returns a Scalar corresponding to the hash of the first coordinate
    let mut has = Sha3_512::new();
    has.input(p.compress().to_bytes());

    Scalar::from_hash(has)
}

/// Prove that the pc is the encryption of k1*g for randomness rcom
pub fn prove1(rcom: Scalar, g: RistrettoPoint, h: RistrettoPoint, k1: Scalar, pc0: RistrettoPoint, pc1: RistrettoPoint)
        -> (RistrettoPoint,RistrettoPoint,Scalar,Scalar) {
    let mut rng = OsRng::new().unwrap();
    let kk = Scalar::random(&mut rng);
    let kr = Scalar::random(&mut rng);
    let prkh = kk*g + kr*h;
    let prg = kr*g;
    let e = hashp3_to_scal(prkh, prg, pc0, pc1);

    (prkh, prg, k1 * e + kk, rcom * e + kr)

}

/// Check the validity of the PoK of the encrypted exponent
pub fn verproof(pr: (RistrettoPoint,RistrettoPoint,Scalar,Scalar), pc:(RistrettoPoint,RistrettoPoint), g:RistrettoPoint, h:RistrettoPoint)
        -> bool {
    let e = hashp3_to_scal(pr.0,pr.1,pc.0,pc.1);
    e*pc.0 + pr.1 == pr.3 *g &&    e*pc.1 + pr.0== pr.3 *h + pr.2*g

}


/// Flow 1 generates an ephemereal secret key
pub fn flow1(g: RistrettoPoint, h: RistrettoPoint)
        -> ((Scalar, RistrettoPoint),((RistrettoPoint,RistrettoPoint),(RistrettoPoint,RistrettoPoint,Scalar,Scalar))) {
    let mut rng = OsRng::new().unwrap();
    let k1 = Scalar::random(&mut rng);
    let r1 = k1*g;
    let rcom = Scalar::random(&mut rng);
    let pc = (rcom * g, rcom*h + r1);
    let pr1 = prove1(rcom, g, h, k1, pc.0, pc.1);

        ((k1, r1) ,(pc,pr1))
}




/// Flow does the same in reverse
pub fn flow2(g: RistrettoPoint)
        -> (Scalar,(RistrettoPoint,(RistrettoPoint, Scalar))) {
    let mut rng = OsRng::new().unwrap();
    let k2 = Scalar::random(&mut rng);
    let r2 = k2*g;
    let pr2 = prove2(k2, g, r2);

    (k2,(r2,pr2))
}


//U1 then samples hk; hp for the language R. It samples u; w 2 R. And sends c = u
//and hp and a proof he knows the witness w associated with u. It also sends
//d = Enc¹hp;H¹mºº with a PoK of H¹mº
//U1 sets the ephemeral key to be R = k1R2, and sets R = ¹rx; ryº; r = rx mod q
//and sends EK = Enc¹hp; rº together with a PoK of r.


/// Flow 3, computes the shared key k, takes r as its x coordinate, and encrypts it in ed
/// It also encrypts H(mes) in d
pub fn flow3(r2: RistrettoPoint, k1: Scalar, g: RistrettoPoint, mes: String)
        -> ((RistrettoPoint,Scalar), (RistrettoPoint, (RistrettoPoint,RistrettoPoint)),(RistrettoPoint,RistrettoPoint)) {
    let mut rng = OsRng::new().unwrap();
    let w = Scalar::random(&mut rng);
    let hk = Scalar::random(&mut rng);
    let hp = hk*g;
    let u = w*g;
    let v = w*hp;

    let po = RistrettoPoint::hash_from_bytes::<Sha3_512>(mes.as_bytes()); // Mes -> Point
    let d = (u, v + po); // Encrypts H(m)

    let k=k1*r2;
    let s = Scalar::random(&mut rng);
    let ed = (s*g, s*hp + k); // Need to encrypt K.1

    ((k,hk),(hp,d),ed)
}

// U2 checks the validity of the proof.
// U2 computes c1 = eval_scal¹hp; d; k􀀀12º, c2 = eval_scal¹hp; EK; k􀀀12 x2º, c3 =
//EvalSum¹hp; c1; c2º. It sends c3

fn eval_scal(d: (RistrettoPoint,RistrettoPoint), k: Scalar, hp: RistrettoPoint, g:RistrettoPoint)
            -> (RistrettoPoint,RistrettoPoint){
    let mut rng = OsRng::new().unwrap();
    let w = Scalar::random(&mut rng);
    (k * d.0 + w*g, k*d.1 + w*hp)
}

fn eval_mult(c1: (RistrettoPoint,RistrettoPoint), c2: (RistrettoPoint,RistrettoPoint), hp: RistrettoPoint, g:RistrettoPoint)
        -> (RistrettoPoint,RistrettoPoint) {
    let mut rng = OsRng::new().unwrap();
    let w = Scalar::random(&mut rng);
    (c1.0 + c2.0 + w*g, c1.1 + c2.1 + w*hp)
}

pub fn flow4(d: (RistrettoPoint,RistrettoPoint), x2: Scalar,ed: (RistrettoPoint,RistrettoPoint), k2: Scalar, hp:RistrettoPoint, g:RistrettoPoint)
            -> (RistrettoPoint,RistrettoPoint) {
    let c1=eval_scal(d,k2.invert(),hp,g);
    let c2=eval_scal(ed,x2*(k2.invert()),hp,g);
    let c3=eval_mult(c1,c2,hp,g);

    c3  //  c3 !!!
}

pub fn recover(hk:Scalar, c3: (RistrettoPoint,RistrettoPoint), k1: Scalar)
        -> (RistrettoPoint) {
    let alpha = c3.1 - hk*c3.0;
    let t = k1.invert()*alpha;  // Does not work
    //s=min(t,q-t)
    t

}

#[cfg(test)]
mod test {
    use super::*;

    fn do_key_init_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (g,_h) = crs_gen();

        let (_sk,(pk,pr)) = key_init(g);

// need to be changed when ZKProof

        verproof2(pr, pk, g) && should_succeed
    }

    #[test]
    fn dsa_ki_success() {
        assert_eq!(do_key_init_test(true), true);
    }

    #[test]
    fn dsa_ki_fail() {
        assert_eq!(do_key_init_test(false), false);
    }

    fn do_flow1_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (g,h) = crs_gen();

        let (_sk,(pk,pr)) = key_init(g);

        let ((k1, r1),(pc,pr1)) = flow1(g,h);

        // need to be changed when ZKProof

        if verproof2(pr,pk,g) && verproof(pr1,pc,g,h) && should_succeed{
            return k1*g == r1;
        }
        else
        {
            return false;
        }
    }

    #[test]
    fn dsa_f1_success() {
        assert_eq!(do_flow1_test(true), true);
    }

    #[test]
    fn dsa_f1_fail() {
        assert_eq!(do_flow1_test(false), false);
    }

    fn do_flow2_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (g,h) = crs_gen();

        let (_sk,(pk,pr)) = key_init(g);

        let ((_k1, _r1),(pc,pr1)) = flow1(g,h);

        let (_k2,(r2,pr2)) = flow2(g);

        // need to be changed when ZKProof

        verproof2(pr,pk,g) && verproof(pr1,pc,g,h) && verproof2(pr2, r2,g) && should_succeed
    }



    #[test]
    fn dsa_f2_success() {
        assert_eq!(do_flow2_test(true), true);
    }

    #[test]
    fn dsa_f2_fail() {
        assert_eq!(do_flow2_test(false), false);
    }

    fn do_flow3_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (g,h) = crs_gen();

        let (_sk,(pk,pr)) = key_init(g);

        let ((k1, r1),(pc,pr1)) = flow1(g,h);

        let (k2,(r2,pr2)) = flow2(g);

        let mes= "Brocolis are awesome".to_string();

        let ((k,hk),(hp,_c),_d) = flow3(r2,k1,g,mes);
        if hp == g * hk && verproof2(pr,pk,g) && verproof(pr1,pc,g,h) && verproof2(pr2, r2,g) && should_succeed {
            return k==k2*r1
        }
        else {
            return false
        }

    }



    #[test]
    fn dsa_f3_success() {
        assert_eq!(do_flow3_test(true), true);
    }

    #[test]
    fn dsa_f3_fail() {
        assert_eq!(do_flow3_test(false), false);
    }

    fn do_flow4_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (g,h) = crs_gen();

        let (sk,(pk,pr)) = key_init(g);

        let ((k1, _r1),(pc,pr1)) = flow1(g,h);

        let (k2,(r2,pr2)) = flow2(g);

        let mes= "Brocolis are awesome".to_string();

        let ((_k,hk),(hp,c),d) = flow3(r2,k1,g,mes);

        let c3=flow4(c,sk,d,k2,hp,g);

        let a=recover(hk,c3,k1);

        let mes= "Brocolis are awesome".to_string();

        let p = RistrettoPoint::hash_from_bytes::<Sha3_512>(mes.as_bytes());

        if  p + r2*sk*k1 == k2 *k1 *a && verproof2(pr,pk,g) && verproof(pr1,pc,g,h) && verproof2(pr2, r2,g) && should_succeed {
            return true
        }
        else {
            return false
        }
        // need to be changed when ZKProof



    }



    #[test]
    fn dsa_f4_success() {
        assert_eq!(do_flow4_test(true), true);
    }

    #[test]
    fn dsa_f4_fail() {
        assert_eq!(do_flow4_test(false), false);
    }



}
