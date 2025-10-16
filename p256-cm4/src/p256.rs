use crate::{Signature, VerifyingKey};

impl From<&p256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(key: &p256::ecdsa::VerifyingKey) -> Self {
        let affine = key.to_encoded_point(false);

        let mut x = [0u32; 8];
        let mut y = [0u32; 8];

        let _convert_success = crate::octet_string_to_point(&mut x, &mut y, affine.as_bytes());

        debug_assert!(_convert_success);

        Self { x, y }
    }
}

impl From<p256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(key: p256::ecdsa::VerifyingKey) -> Self {
        Self::from(&key)
    }
}

impl From<&p256::ecdsa::Signature> for Signature {
    fn from(signature: &p256::ecdsa::Signature) -> Self {
        let (r, s) = signature.split_bytes();

        let r = r.as_slice();
        let s = s.as_slice();

        Self::from_parts(r.try_into().unwrap(), s.try_into().unwrap()).unwrap()
    }
}

impl From<p256::ecdsa::Signature> for Signature {
    fn from(signature: p256::ecdsa::Signature) -> Self {
        Self::from(&signature)
    }
}
