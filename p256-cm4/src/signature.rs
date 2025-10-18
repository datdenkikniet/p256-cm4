use generic_array::typenum::U32;

use crate::{Signature, VerifyingKey};

impl<D> signature::DigestVerifier<D, crate::Signature> for VerifyingKey
where
    D: signature::digest::Digest<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), signature::Error> {
        let digest = digest.finalize();

        self.verify_prehash(digest.as_ref(), signature)
            .then_some(())
            .ok_or_else(signature::Error::new)
    }
}

#[cfg(feature = "p256")]
impl<D> signature::DigestVerifier<D, p256::ecdsa::Signature> for VerifyingKey
where
    D: signature::digest::Digest<OutputSize = U32>,
{
    fn verify_digest(
        &self,
        digest: D,
        signature: &p256::ecdsa::Signature,
    ) -> Result<(), signature::Error> {
        let signature = signature.into();

        let digest = digest.finalize();

        self.verify_prehash(digest.as_ref(), &signature)
            .then_some(())
            .ok_or_else(signature::Error::new)
    }
}
