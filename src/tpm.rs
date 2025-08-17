use std::env;
use std::sync::{OnceLock, RwLock};

use tss_esapi::{Context, Error, TctiNameConf};
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::constants::StartupType;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::{CreateKeyResult, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParameters, Signature, SignatureScheme};
use tss_esapi::tss2_esys::{TPMT_TK_HASHCHECK};

#[derive(Debug)]
pub struct Tpm {
    ctx: Context,
    handle: TpmHandle
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

        let handle_value = env::var("TUKS_TPM_PRIMARY_HANDLE").ok()
            .and_then(|s| {
                if s.starts_with("0x") || s.starts_with("0X") {
                    u32::from_str_radix(&s[2..], 16).ok()
                } else {
                    s.parse::<u32>().ok()
                }
            })
            .expect("Failed to get TPM primary handle");

        Ok(Tpm {
            ctx,
            handle: TpmHandle::Persistent(PersistentTpmHandle::new(handle_value)?)
        })
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        self.ctx.shutdown(StartupType::State).unwrap();
    }
}

impl Tpm {
    pub fn create_ecdsa_key(&mut self) -> Result<CreateKeyResult, Error> {
        let public = create_ecdsa_public(EccPoint::default())?;

        self.ctx.execute_with_nullauth_session(|ctx| {
            let primary_handle = ctx.tr_from_tpm_public(self.handle)?;
            let key = ctx.create(
                primary_handle.into(),
                public,
                None,
                None,
                None,
                None
            )?;

            Ok(key)
        })
    }

    pub fn sign_ecdsa(&mut self, public: EccPoint, private: Private, data: &[u8]) -> Result<Signature, Error> {
        let public = create_ecdsa_public(public)?;

        self.ctx.execute_with_nullauth_session(|ctx| {
            let primary_handle = ctx.tr_from_tpm_public(self.handle)?;
            let key_handle = ctx.load(primary_handle.into(), private, public)?;
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

            Ok(sig)
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
