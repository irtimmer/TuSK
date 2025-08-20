// Based on default key store implementation from OpenSK

// Copyright 2025 Iwan Timmer
// Copyright 2022-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use arrayref::array_ref;

use opensk::api::crypto::HASH_SIZE;
use opensk::api::crypto::aes256::Aes256;
use opensk::api::crypto::hkdf256::Hkdf256;
use opensk::api::crypto::hmac256::Hmac256;
use opensk::env::{AesKey, Env, Hkdf, Hmac};
use opensk::api::key_store::{CredentialSource, Error, KeyStore};
use opensk::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use opensk::ctap::{cbor_read, cbor_write};
use opensk::ctap::data_formats::{extract_byte_string, extract_map, CredentialProtectionPolicy};
use opensk::ctap::secret::Secret;

use sk_cbor::{self as cbor, destructure_cbor_map};
use sk_cbor::cbor_map_options;

use tss_esapi::structures::{EccParameter, EccPoint};

use crate::env::TuskEnv;
use crate::tpm::get_tpm;

// CBOR credential IDs consist of
// - 1   byte : version number
// - 208 bytes: encrypted block of the key handle cbor,
// - 32  bytes: HMAC-SHA256 over everything else.
const CBOR_CREDENTIAL_ID_SIZE: usize = 241;
const MAX_PADDING_LENGTH: u8 = 0xCF;

const CBOR_CREDENTIAL_ID_VERSION: u8 = 0x01;

const STATIC_MASTER_PUBLIC_KEY: [u8; 64] = [
    0xcd, 0x47, 0x43, 0xfd, 0x92, 0x37, 0xd4, 0xd9, 0x37, 0xd9, 0x4f, 0x2b, 0xe8, 0xa5, 0x09, 0x62,
    0xc2, 0x30, 0xe9, 0xf6, 0x1c, 0xfe, 0x3b, 0x55, 0xdd, 0xee, 0x78, 0x87, 0x2d, 0x47, 0x89, 0x27,
    0x5c, 0xbc, 0x1b, 0x82, 0x92, 0x81, 0x1f, 0x3e, 0xb8, 0xdc, 0x4d, 0x6e, 0x5c, 0x50, 0xdc, 0xca,
    0xab, 0x2c, 0xd2, 0x78, 0xc8, 0x3f, 0x2f, 0x14, 0xea, 0x0e, 0xa0, 0x80, 0xbb, 0xe0, 0x4e, 0x5e
];

/// CBOR map keys for serialized credential IDs.
enum CredentialSourceField {
    PrivateKey = 0,
    CredProtectPolicy = 1,
    CredBlob = 2,
}

impl From<CredentialSourceField> for cbor::Value {
    fn from(field: CredentialSourceField) -> cbor::Value {
        (field as u64).into()
    }
}

impl KeyStore for TuskEnv {
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn wrap_credential(&mut self, credential: CredentialSource) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        let cbor = cbor_map_options! {
          CredentialSourceField::PrivateKey => credential.wrapped_private_key,
          CredentialSourceField::CredProtectPolicy => credential.cred_protect_policy,
          CredentialSourceField::CredBlob => credential.cred_blob,
        };
        cbor_write(cbor, &mut payload).map_err(|_| Error)?;
        add_padding(&mut payload)?;

        let master_keys = get_master_keys()?;
        let aes_key = AesKey::<TuskEnv>::new(&master_keys.encryption);
        let encrypted_payload =
            aes256_cbc_encrypt::<TuskEnv>(self.rng(), &aes_key, &payload, false)?;
        let mut credential_id = encrypted_payload;
        credential_id.insert(0, CBOR_CREDENTIAL_ID_VERSION);

        credential_id.extend(&credential.rp_id_hash);
        let mut id_hmac = [0; HASH_SIZE];
        Hmac::<TuskEnv>::mac(
            &master_keys.authentication,
            &credential_id[..],
            &mut id_hmac,
        );
        credential_id.truncate(credential_id.len() - HASH_SIZE);
        credential_id.extend(&id_hmac);

        Ok(credential_id)
    }

    fn unwrap_credential(
        &mut self,
        bytes: &[u8],
        rp_id_hash: &[u8],
    ) -> Result<Option<CredentialSource>, Error> {
        if bytes.len() < CBOR_CREDENTIAL_ID_SIZE {
            return Ok(None);
        }
        let mut message = bytes.to_vec();
        message.truncate(message.len() - HASH_SIZE);
        message.extend(rp_id_hash);

        let hmac_message_size = bytes.len() - HASH_SIZE;
        let master_keys = get_master_keys()?;
        if !Hmac::<TuskEnv>::verify(
            &master_keys.authentication,
            &message,
            array_ref![bytes, hmac_message_size, HASH_SIZE],
        ) {
            return Ok(None);
        }

        let plaintext = match bytes[0] {
            CBOR_CREDENTIAL_ID_VERSION => {
                let aes_key = AesKey::<TuskEnv>::new(&master_keys.encryption);
                aes256_cbc_decrypt::<TuskEnv>(&aes_key, &bytes[1..hmac_message_size], false)?
            }
            _ => return Ok(None),
        };

        let payload = remove_padding(&plaintext)?;
        let cbor = cbor_read(&payload)?;
        destructure_cbor_map! {
            let {
                CredentialSourceField::PrivateKey => wrapped_private_key,
                CredentialSourceField::CredProtectPolicy => cred_protect_policy,
                CredentialSourceField::CredBlob => cred_blob,
            } = extract_map(cbor)?;
        }

        let wrapped_private_key = match wrapped_private_key {
            Some(key) => key,
            None => return Ok(None),
        };
        let cred_protect_policy = cred_protect_policy
            .map(CredentialProtectionPolicy::try_from)
            .transpose()?;
        let cred_blob = cred_blob.map(extract_byte_string).transpose()?;

        let mut rp_id_hash_buffer = [0u8; HASH_SIZE];
        rp_id_hash_buffer.copy_from_slice(rp_id_hash);

        Ok(Some(CredentialSource {
            wrapped_private_key: wrapped_private_key,
            rp_id_hash: rp_id_hash_buffer,
            cred_protect_policy: cred_protect_policy,
            cred_blob: cred_blob,
        }))
    }

    fn cred_random(&mut self, has_uv: bool) -> Result<Secret<[u8; 32]>, Error> {
        Ok(get_master_keys()?.cred_random[has_uv as usize].clone())
    }

    fn encrypt_pin_hash(&mut self, plain: &[u8; 16]) -> Result<[u8; 16], Error> {
        Ok(*plain)
    }

    fn decrypt_pin_hash(&mut self, cipher: &[u8; 16]) -> Result<Secret<[u8; 16]>, Error> {
        Ok(Secret::from_exposed_secret(*cipher))
    }

    fn reset(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Wrapper for master keys.
struct MasterKeys {
    /// Master encryption key.
    encryption: Secret<[u8; 32]>,

    /// Master authentication key.
    authentication: Secret<[u8; 32]>,

    /// Cred random keys (without and with UV in that order).
    cred_random: [Secret<[u8; 32]>; 2],
}

fn get_master_keys() -> Result<MasterKeys, Error> {
    let public_key = EccPoint::new(
        EccParameter::try_from(&STATIC_MASTER_PUBLIC_KEY[0..32]).unwrap(),
        EccParameter::try_from(&STATIC_MASTER_PUBLIC_KEY[32..64]).unwrap(),
    );

    let shared_key = get_tpm().write().map_err(|_| Error)?
        .zgen(public_key).map_err(|_| Error)?
        .x().to_vec();

    let mut encryption: Secret<[u8; 32]> = Secret::default();
    Hkdf::<TuskEnv>::hkdf_empty_salt_256(shared_key.as_ref(), b"encryption", &mut encryption);
    let mut authentication: Secret<[u8; 32]> = Secret::default();
    Hkdf::<TuskEnv>::hkdf_empty_salt_256(shared_key.as_ref(), b"authentication", &mut authentication);
    let mut cred_random_no_uv: Secret<[u8; 32]> = Secret::default();
    Hkdf::<TuskEnv>::hkdf_empty_salt_256(shared_key.as_ref(), b"cred_random_no_uv", &mut cred_random_no_uv);
    let mut cred_random_with_uv: Secret<[u8; 32]> = Secret::default();
    Hkdf::<TuskEnv>::hkdf_empty_salt_256(shared_key.as_ref(), b"cred_random_with_uv", &mut cred_random_with_uv);
    Ok(MasterKeys {
        encryption,
        authentication,
        cred_random: [cred_random_no_uv, cred_random_with_uv],
    })
}

/// Pad data to MAX_PADDING_LENGTH+1 (256) bytes using PKCS padding scheme.
///
/// Let N = 192 - data.len(), the PKCS padding scheme would pad N bytes of N after the data.
fn add_padding(data: &mut Vec<u8>) -> Result<(), Error> {
    // The data should be between 1 to MAX_PADDING_LENGTH bytes for the padding scheme to be valid.
    if data.is_empty() || data.len() > MAX_PADDING_LENGTH as usize {
        return Err(Error);
    }
    let pad_length = MAX_PADDING_LENGTH - (data.len() as u8 - 1);
    data.extend(core::iter::repeat(pad_length).take(pad_length as usize));
    Ok(())
}

fn remove_padding(data: &[u8]) -> Result<&[u8], Error> {
    if data.len() != MAX_PADDING_LENGTH as usize + 1 {
        // This is an internal error instead of corrupted credential ID which we should just ignore because
        // we've already checked that the HMAC matched.
        return Err(Error);
    }
    let pad_length = *data.last().unwrap();
    if pad_length == 0 || pad_length > MAX_PADDING_LENGTH {
        return Err(Error);
    }
    if !data[(data.len() - pad_length as usize)..]
        .iter()
        .all(|x| *x == pad_length)
    {
        return Err(Error);
    }
    Ok(&data[..data.len() - pad_length as usize])
}
