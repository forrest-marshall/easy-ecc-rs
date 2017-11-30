//! types and functions for signing operations on the `secp256r1` curve.
use libc::{uint8_t,c_int};


/// size of curve.
const BYTES: usize = 32;


/// a public ecc key on the `secp256r1` curve.
pub struct Public([u8;BYTES+1]);
impl_newtype_bytearray_ext!(Public,BYTES+1);
impl_serhex_bytearray!(Public,BYTES+1);


/// a secret ecc key on the `secp256r1` curve.
#[derive(Debug,Default,PartialEq,Eq)]
pub struct Secret([u8;BYTES]);
impl_newtype_bytearray!(Secret,BYTES);
impl_serhex_bytearray!(Secret,BYTES);

/// an ecc signature on the `secp256r1` curve.
pub struct Signature([u8;BYTES*2]);
impl_newtype_bytearray_ext!(Signature,BYTES*2);
impl_serhex_bytearray!(Signature,BYTES*2);

/// generate a new ecc keypair.
pub fn keygen(public: &mut Public, secret: &mut Secret) -> Result<(),()> {
    let rslt = unsafe {
        ecc_make_key(&mut public.0 as *mut [u8;BYTES+1], &mut secret.0 as *mut [u8;BYTES])
    };
    match rslt {
        1 => Ok(()),
        _ => Err(())
    }
}


/// generate a new ecc signature.
pub fn sign(key: &Secret, msg: &[u8;BYTES], sig: &mut Signature) -> Result<(),()> {
    let rslt = unsafe {
        ecdsa_sign(&key.0 as *const [u8;BYTES], msg as *const [u8;BYTES], &mut sig.0 as *mut [u8;BYTES*2])
    };
    match rslt {
        1 => Ok(()),
        _ => Err(())
    }
}


/// verify an ecc signature.
pub fn verify(key: &Public, msg: &[u8;BYTES], sig: &Signature) -> Result<(),()> {
    let rslt = unsafe {
        ecdsa_verify(&key.0 as *const [u8;BYTES+1], msg as *const [u8;BYTES], &sig.0 as *const [u8;BYTES*2])
    };
    match rslt {
        1 => Ok(()),
        _ => Err(())
    }
}


// ffi function defs.
#[link(name = "p256", kind = "static")]
extern {
    // int ecc_make_key(uint8_t p_publicKey[ECC_BYTES+1], uint8_t p_privateKey[ECC_BYTES]);
    fn ecc_make_key(p_publicKey: *mut [uint8_t; BYTES+1], p_privateKey: *mut [uint8_t;BYTES]) -> c_int;

    // int ecdsa_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2]);
    fn ecdsa_sign(p_privateKey: *const [uint8_t;BYTES], p_hash: *const [uint8_t; BYTES], p_signature: *mut [uint8_t; BYTES * 2]) -> c_int;

    // int ecdsa_verify(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2]);
    fn ecdsa_verify(p_publicKey: *const [uint8_t;BYTES+1], p_hash: *const [uint8_t;BYTES], p_signature: *const [uint8_t;BYTES*2]) -> c_int;
}


#[cfg(test)]
mod tests {
    use secp256r1::{BYTES,Public,Secret,Signature,keygen,sign,verify};

    #[test]
    fn keygen_ok() {
        let mut public = Public::default();
        let mut secret = Secret::default();
        keygen(&mut public, &mut secret).unwrap();

        assert!(public != Public::default());
        assert!(secret != Secret::default());
    }

    #[test]
    fn signing_ok() {
        let mut public = Public::default();
        let mut secret = Secret::default();
        keygen(&mut public, &mut secret).unwrap();
        let mut sig = Signature::default();
        let mut msg = [0u8;BYTES];
        msg[0] = 1; msg[2] = 3; msg[4] = 5;
        sign(&secret,&msg,&mut sig).unwrap();
        verify(&public,&msg,&sig).unwrap();
    }

    #[test]
    #[should_panic]
    fn signing_err() {
        let mut public = Public::default();
        let mut secret = Secret::default();
        keygen(&mut public, &mut secret).unwrap();
        let mut sig = Signature::default();
        let mut msg = [0u8;BYTES];
        msg[0] = 1; msg[2] = 3; msg[4] = 5;
        sign(&secret,&msg,&mut sig).unwrap();
        msg[0] ^= 0xff;
        verify(&public,&msg,&sig).unwrap();
    }
    
    #[test]
    fn precomputed_ok() {
        let public = Public::from([
            0x03, 0x94, 0x58, 0xdd, 0x87, 0xbd, 0xb4, 0x7d,
            0xe4, 0x8b, 0xb9, 0x47, 0x0b, 0x8c, 0x25, 0xcb,
            0x5f, 0x94, 0x06, 0x90, 0x7c, 0x45, 0xd8, 0x65,
            0x26, 0x5a, 0xea, 0x38, 0xd6, 0xb0, 0xbb, 0x37,
            0x80
        ]);
        let secret = Secret::from([
            0xab, 0x73, 0x28, 0xe4, 0xbd, 0x9b, 0xea, 0xd4,
            0x75, 0xdd, 0x7c, 0xd8, 0x99, 0xc1, 0xba, 0x91,
            0x18, 0xc8, 0xb1, 0xfc, 0xb9, 0x0c, 0x93, 0xa8,
            0x85, 0x85, 0x37, 0xd3, 0x6e, 0x3c, 0x1e, 0x98
        ]);
        let mut sig = Signature::default();
        let mut msg = [0u8;BYTES];
        msg[6] = 7; msg[8] = 9; msg[10] = 11;
        sign(&secret,&msg,&mut sig).unwrap();
        verify(&public,&msg,&sig).unwrap();
    }


    #[test]
    #[should_panic]
    fn precomputed_err() {
        let public = Public::from([
            0x03, 0x94, 0x58, 0xdd, 0x87, 0xbd, 0xb4, 0x7d,
            0xe4, 0x8b, 0xb9, 0x47, 0x0b, 0x8c, 0x25, 0xcb,
            0x5f, 0x94, 0x06, 0x90, 0x7c, 0x45, 0xd8, 0x65,
            0x26, 0x5a, 0xea, 0x38, 0xd6, 0xb0, 0xbb, 0x37,
            0x80
        ]);
        let secret = Secret::from([
            0xab, 0x73, 0x28, 0xe4, 0xbd, 0x9b, 0xea, 0xd4,
            0x75, 0xdd, 0x7c, 0xd8, 0x99, 0xc1, 0xba, 0x91,
            0x18, 0xc8, 0xb1, 0xfc, 0xb9, 0x0c, 0x93, 0xa8,
            0x85, 0x85, 0x37, 0xd3, 0x6e, 0x3c, 0x1e, 0x98
        ]);
        let mut sig = Signature::default();
        let mut msg = [0u8;BYTES];
        msg[6] = 7; msg[8] = 9; msg[10] = 11;
        sign(&secret,&msg,&mut sig).unwrap();
        msg[10] ^= 0xff;
        verify(&public,&msg,&sig).unwrap();
    }
}
