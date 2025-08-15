use opensk::api::customization::{Customization, AAGUID_LENGTH};
use opensk::ctap::data_formats::{CredentialProtectionPolicy, EnterpriseAttestationMode};

const TUSK_AAGUID: [u8; AAGUID_LENGTH] = [
    0x18, 0xed, 0x54, 0x76, 0x26, 0xe3, 0x46, 0xa2,
    0x80, 0xa5, 0xd9, 0x83, 0xb3, 0xbd, 0xe8, 0x56
];

pub struct TuskCustomization {
    allows_pin_protocol_v1: bool,
    default_min_pin_length: u8,
    enforce_always_uv: bool,
    max_pin_retries: u8,
    use_batch_attestation: bool
}

impl TuskCustomization {
    pub fn new() -> Self {
        Self {
            allows_pin_protocol_v1: true,
            default_min_pin_length: 4,
            enforce_always_uv: false,
            max_pin_retries: 8,
            use_batch_attestation: false,
        }
    }
}

impl Customization for TuskCustomization {
    fn aaguid(&self) -> &'static [u8; AAGUID_LENGTH] {
        &TUSK_AAGUID
    }

    fn allows_pin_protocol_v1(&self) -> bool {
        self.allows_pin_protocol_v1
    }

    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        Some(CredentialProtectionPolicy::UserVerificationOptional)
    }

    fn default_min_pin_length(&self) -> u8 {
        self.default_min_pin_length
    }

    fn default_min_pin_length_rp_ids(&self) -> Vec<String> {
        Vec::new()
    }

    fn enforce_always_uv(&self) -> bool {
        self.enforce_always_uv
    }

    fn enterprise_attestation_mode(&self) -> Option<EnterpriseAttestationMode> {
        None
    }

    fn is_enterprise_rp_id(&self, _rp_id: &str) -> bool {
        false
    }

    fn max_msg_size(&self) -> usize {
        // CTAP2 specification requires a maximum message size of 7609 bytes
        7609
    }

    fn max_pin_retries(&self) -> u8 {
        self.max_pin_retries
    }

    fn use_batch_attestation(&self) -> bool {
        self.use_batch_attestation
    }

    fn use_signature_counter(&self) -> bool {
        true
    }

    fn max_cred_blob_length(&self) -> usize {
        64 // OpenSK encodes blobs in credential ID, so the maximum length is 64 bytes
    }

    fn max_credential_count_in_list(&self) -> Option<usize> {
        None
    }

    fn max_large_blob_array_size(&self) -> usize {
        0x100000 // 1 MB
    }

    fn max_rp_ids_length(&self) -> usize {
        self.max_supported_resident_keys()
    }

    fn max_supported_resident_keys(&self) -> usize {
        u16::MAX as usize // Give a generous but reasonable limit
    }
}
