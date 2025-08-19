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
use opensk::api::crypto::hmac256::Hmac256;
use opensk::api::persist::Persist;
use opensk::env::{AesKey, Env, Hmac};
use opensk::api::key_store::{CredentialSource, Error, KeyStore};
use opensk::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use opensk::ctap::{cbor_read, cbor_write};
use opensk::ctap::data_formats::{extract_byte_string, extract_map, CredentialProtectionPolicy};
use opensk::ctap::secret::Secret;

use rand::RngCore;

use sk_cbor::{self as cbor, destructure_cbor_map};
use sk_cbor::cbor_map_options;

use crate::env::TuskEnv;

// CBOR credential IDs consist of
// - 1   byte : version number
// - 208 bytes: encrypted block of the key handle cbor,
// - 32  bytes: HMAC-SHA256 over everything else.
const CBOR_CREDENTIAL_ID_SIZE: usize = 241;
const MAX_PADDING_LENGTH: u8 = 0xCF;

const CBOR_CREDENTIAL_ID_VERSION: u8 = 0x01;

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

        let master_keys = get_master_keys(self)?;
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
        let master_keys = get_master_keys(self)?;
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
        Ok(get_master_keys(self)?.cred_random[has_uv as usize].clone())
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

fn get_master_keys(env: &mut impl Env) -> Result<MasterKeys, Error> {
    let master_keys = match env.persist().key_store_bytes()? {
        Some(x) if x.len() == 128 => x,
        Some(_) => return Err(Error),
        None => {
            let mut master_keys = Secret::new(128);
            env.rng().fill_bytes(&mut master_keys);
            env.persist().write_key_store_bytes(&master_keys)?;
            master_keys
        }
    };
    let mut encryption: Secret<[u8; 32]> = Secret::default();
    encryption.copy_from_slice(array_ref![master_keys, 0, 32]);
    let mut authentication: Secret<[u8; 32]> = Secret::default();
    authentication.copy_from_slice(array_ref![master_keys, 32, 32]);
    let mut cred_random_no_uv: Secret<[u8; 32]> = Secret::default();
    cred_random_no_uv.copy_from_slice(array_ref![master_keys, 64, 32]);
    let mut cred_random_with_uv: Secret<[u8; 32]> = Secret::default();
    cred_random_with_uv.copy_from_slice(array_ref![master_keys, 96, 32]);
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
