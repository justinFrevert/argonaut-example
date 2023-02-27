#![cfg_attr(not(feature = "std"), no_std)]

use sp_runtime_interface::runtime_interface;
use pqcrypto_falcon::falcon512_verify_detached_signature;

#[runtime_interface]
pub trait ArgonautPrimitive {
    fn falcon_verify(signature: &[u8], msg: &[u8], pk: &[u8]) {
        use pqcrypto_traits::sign::DetachedSignature;
        use pqcrypto_traits::sign::PublicKey;

        let detached_sig = &DetachedSignature::from_bytes(signature).unwrap();
        let pk = &PublicKey::from_bytes(pk).unwrap();
        falcon512_verify_detached_signature(detached_sig, msg, pk);
    }
}