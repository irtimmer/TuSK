use std::sync::{OnceLock, RwLock};

use tss_esapi::{Context, Error, TctiNameConf};
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::constants::StartupType;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{CreateKeyResult, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParameters, Signature, SignatureScheme, SymmetricDefinitionObject};
use tss_esapi::tss2_esys::{TPMT_TK_HASHCHECK};

#[derive(Debug)]
pub struct Tpm {
    ctx: Context
}

pub fn get_tpm() -> &'static RwLock<Tpm> {
    static TPM: OnceLock<RwLock<Tpm>> = OnceLock::new();
    TPM.get_or_init(|| RwLock::new(Tpm::new().expect("Failed to initialize TPM")))
}

impl Tpm {
    pub fn new() -> Result<Self, Error> {
        let tcti_cfg = TctiNameConf::from_environment_variable()?;
        let mut ctx = Context::new(tcti_cfg)?;
        ctx.startup(StartupType::Clear)?;

        Ok(Tpm {
            ctx
        })
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        self.ctx.shutdown(StartupType::State).unwrap();
    }
}

impl Tpm {
    pub fn create_primary_storage_key(&mut self) -> Result<KeyHandle, Error> {
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(ObjectAttributes::builder()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_decrypt(true)
                .build()?)
            .with_ecc_parameters(PublicEccParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::AES_256_CFB)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_ecc_scheme(EccScheme::Null)
                .with_restricted(true)
                .with_is_decryption_key(true)
                .build()?)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        self.create_primary_key(public)
    }

    pub fn create_primary_master_key(&mut self) -> Result<KeyHandle, Error> {
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(ObjectAttributes::builder()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(false)
                .with_decrypt(true)
                .build()?)
            .with_ecc_parameters(PublicEccParameters::builder()
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_restricted(false)
                .with_is_decryption_key(true)
                .build()?)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        self.create_primary_key(public)
    }

    fn create_primary_key(&mut self, public: Public) -> Result<KeyHandle, Error> {
        self.ctx.execute_with_nullauth_session(|ctx| {
            let key = ctx.create_primary(
                Hierarchy::Owner,
                public,
                None,
                None,
                None,
                None
            )?;

            Ok(key.key_handle)
        })
    }

    pub fn create_ecdsa_key(&mut self) -> Result<CreateKeyResult, Error> {
        let primary_handle = self.create_primary_storage_key()?;
        let public = create_ecdsa_public(EccPoint::default())?;

        self.ctx.execute_with_nullauth_session(|ctx| {
            let key = ctx.create(
                primary_handle,
                public,
                None,
                None,
                None,
                None
            )?;
            ctx.flush_context(primary_handle.into())?;

            Ok(key)
        })
    }

    pub fn sign_ecdsa(&mut self, public: EccPoint, private: Private, data: &[u8]) -> Result<Signature, Error> {
        let primary_handle = self.create_primary_storage_key()?;
        let public = create_ecdsa_public(public)?;

        self.ctx.execute_with_nullauth_session(|ctx| {
            let key_handle = ctx.load(primary_handle, private, public)?;
            let sig = ctx.sign(
                key_handle,
                Digest::try_from(data)?,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                // temporary workaround because validation is erroneously non-optional in tss_esapi
                HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
                    tag: TPM2_ST_HASHCHECK,
                    hierarchy: TPM2_RH_NULL,
                    digest: Default::default(),
                })?
            )?;

            ctx.flush_context(key_handle.into())?;
            ctx.flush_context(primary_handle.into())?;

            Ok(sig)
        })
    }

    pub fn zgen(&mut self, public: EccPoint) -> Result<EccPoint, Error> {
        let primary_handle = self.create_primary_master_key()?;

        self.ctx.execute_with_nullauth_session(|ctx| {
            let zgen_result = ctx.ecdh_z_gen(primary_handle, public)?;
            ctx.flush_context(primary_handle.into())?;

            Ok(zgen_result)
        })
    }
}

fn create_ecdsa_public(unique: EccPoint) -> Result<Public, Error> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_sensitive_data_origin(true)
            .with_sign_encrypt(true)
            .build()?)
        .with_ecc_parameters(PublicEccParameters::builder()
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_ecc_scheme(EccScheme::Null)
            .with_is_signing_key(true)
            .with_ecc_scheme(EccScheme::create(EccSchemeAlgorithm::EcDsa, Some(HashingAlgorithm::Sha256), None)?)
            .build()?)
        .with_ecc_unique_identifier(unique)
        .build()
}
