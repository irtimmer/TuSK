use ecdsa::{Signature as DerSignature};

use opensk::api::crypto::sha256::Sha256;
use opensk::api::crypto::{Crypto, EC_FIELD_SIZE};
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::rust_crypto::{SoftwareAes256, SoftwareEcdh, SoftwareHkdf256, SoftwareHmac256, SoftwareSha256};
use opensk::api::rng::Rng;

use tss_esapi::structures::{EccSignature, Private, Public, Signature};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::tpm::get_tpm;

pub struct TuskCrypto;

impl Crypto for TuskCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = TpmEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}

pub struct TpmEcdsa;

impl Ecdsa for TpmEcdsa {
    type SecretKey = TpmEcdsaSecretKey;
    type PublicKey = TpmEcdsaPublicKey;
    type Signature = TpmEcdsaSignature;
}

pub struct TpmEcdsaSecretKey {
    public: Public,
    private: Private
}

impl EcSecretKey for TpmEcdsaSecretKey {
    type PublicKey = TpmEcdsaPublicKey;
    type Signature = TpmEcdsaSignature;

    fn random(_rng: &mut impl Rng) -> Self {
        let mut tpm = get_tpm().write().expect("Failed to lock TPM");
        let key = tpm.create_ecdsa_key().expect("Failed to create ECDSA key using TPM");

        Self {
            public: key.out_public,
            private: key.out_private,
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        TpmEcdsaPublicKey(self.public.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let digest = SoftwareSha256::digest(message);
        let mut tpm = get_tpm().write().unwrap();
        let signature = tpm.sign_ecdsa(self.public.clone(), self.private.clone(), &digest)
            .expect("Failed to sign message using TPM");

        match signature {
            Signature::EcDsa(ecdsa_signature) => TpmEcdsaSignature(ecdsa_signature),
            _ => panic!("Unexpected signature type"),
        }
    }

    fn export(&self) -> Vec<u8> {
        let public = self.public.marshall().expect("Failed to marshall public key");
        let mut bytes = Vec::with_capacity(1 + public.len() + self.private.len());
        bytes.push(public.len() as u8);
        bytes.extend_from_slice(&public);
        bytes.extend_from_slice(&self.private);
        bytes
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let public_len = bytes[0] as usize;
        if bytes.len() < 1 + public_len {
            return None;
        }

        let public = Public::unmarshall(&bytes[1..1 + public_len]).ok()?;
        let private = Private::try_from(&bytes[1 + public_len..]).ok()?;
        Some(Self { public, private })
    }
}

pub struct TpmEcdsaPublicKey(Public);

impl EcPublicKey for TpmEcdsaPublicKey {
    type Signature = TpmEcdsaSignature;

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        if let Public::Ecc { unique, .. } = &self.0 {
            x.copy_from_slice(unique.x());
            y.copy_from_slice(unique.y());
        }
    }
}

pub struct TpmEcdsaSignature(EccSignature);

impl EcSignature for TpmEcdsaSignature {

    fn to_der(&self) -> Vec<u8> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(self.0.signature_r());
        s.copy_from_slice(self.0.signature_s());

        DerSignature::<p256::NistP256>::from_scalars(r, s)
            .expect("Failed to create DER signature")
            .to_der()
            .as_bytes()
            .to_vec()
    }
}
