use std::sync::{OnceLock, RwLock};
use std::str::FromStr;

use tss_esapi::{Context, Error, TctiNameConf};
use tss_esapi::attributes::{ObjectAttributes, SessionAttributesBuilder};
use tss_esapi::constants::{SessionType, StartupType};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::interface_types::algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{CreateKeyResult, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParameters, Signature, SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject};
use tss_esapi::tss2_esys::{TPMT_TK_HASHCHECK};

use crate::tpm::handles::HandleGuard;

mod handles;

static TPM: OnceLock<RwLock<Tpm>> = OnceLock::new();

/// Represents a connection to a Trusted Platform Module (TPM).
///
/// This struct serves as the primary interface for interacting with the TPM.
/// It encapsulates the underlying communication context and manages an optional
/// authentication session for privileged operations.
///
/// # Fields
///
/// * `ctx` - A `Context` object for low-level communication with the TPM.
/// * `session` - An optional `AuthSession` for performing authenticated commands.
#[derive(Debug)]
pub struct Tpm {
    ctx: Context,
    session: Option<AuthSession>
}

/// Get a singleton reference to the TPM
///
/// # Warning
/// This function should only be called after the TPM has been initialized using `init_tpm`
pub fn get_tpm() -> &'static RwLock<Tpm> {
    TPM.get().expect("TPM not initialized")
}

/// Initialize the TPM using the specified TCTI
///
/// # Warning
/// This function should only be called once during application startup
pub fn init_tpm(tcti: &str) {
    TPM.set(RwLock::new(Tpm::new(tcti).expect("Failed to initialize TPM")))
        .expect("TPM already initialized");
}

impl Tpm {
    fn new(tcti: &str) -> Result<Self, Error> {
        let tcti_cfg = TctiNameConf::from_str(tcti)?;
        let mut ctx = Context::new(tcti_cfg)?;
        ctx.startup(StartupType::Clear)?;
        let session = ctx.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256
        )?.expect("Failed to start auth session");

        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        ctx.tr_sess_set_attributes(session, attrs, mask)?;

        Ok(Tpm {
            ctx,
            session: Some(session)
        })
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        self.ctx.shutdown(StartupType::State).unwrap();
    }
}

impl Tpm {

    /// Create a primary storage key used for the FIDO signing keys
    fn create_primary_storage_key(&mut self) -> Result<HandleGuard, Error> {
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

    /// Create a primary key used to derive encryption keys uniquely for this TPM
    fn create_primary_master_key(&mut self) -> Result<HandleGuard, Error> {
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

    /// Create a primary key using the specified public template
    fn create_primary_key(&mut self, public: Public) -> Result<HandleGuard, Error> {
        let handle = self.ctx.execute_with_session(self.session, |ctx| {
            let key = ctx.create_primary(
                Hierarchy::Owner,
                public,
                None,
                None,
                None,
                None
            )?;

            Ok(key.key_handle)
        })?;

        Ok(HandleGuard::new(handle, &mut self.ctx))
    }

    /// Generate a new ECDSA key pair
    pub fn create_ecdsa_key(&mut self) -> Result<CreateKeyResult, Error> {
        let session = self.session;
        let primary_key = self.create_primary_storage_key()?;
        let public = create_ecdsa_public(EccPoint::default())?;

        primary_key.ctx.execute_with_session(session, |ctx| ctx.create(
            primary_key.handle,
            public,
            None,
            None,
            None,
            None
        ))
    }

    /// Sign the given data using the specified ECDSA key pair
    pub fn sign_ecdsa(&mut self, public: EccPoint, private: Private, data: &[u8]) -> Result<Signature, Error> {
        let session = self.session;
        let primary_key = self.create_primary_storage_key()?;
        let public = create_ecdsa_public(public)?;

        primary_key.ctx.execute_with_session(session, |ctx| {
            let key_handle = ctx.load(primary_key.handle, private, public)?;
            let key = HandleGuard::new(key_handle, ctx);

            key.ctx.sign(
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
            )
        })
    }

    /// Generate a shared secret using the specified public key and the primary key from the TPM
    pub fn zgen(&mut self, public: EccPoint) -> Result<EccPoint, Error> {
        let session = self.session;
        let primary_key = self.create_primary_master_key()?;
        primary_key.ctx.execute_with_session(session, |ctx| ctx.ecdh_z_gen(primary_key.handle, public))
    }
}

/// Create a new ECDSA public key template that can be used as FIDO credential
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
