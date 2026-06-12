//! MLS transport helpers for Facet.
//!
//! This module keeps OpenMLS responsible for group state and transport
//! encryption, while bilattice remains responsible for hybrid content
//! signatures. The application payload is always a serialized [`SignedContent`].

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::ed25519::signature::Signer as _;
use openmls::prelude::{
    BasicCredential, CredentialWithKey, Extensions, GroupId, KeyPackage, KeyPackageBundle,
    MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, OpenMlsCrypto, OpenMlsProvider, ProcessedMessageContent, ProtocolVersion,
    StagedWelcome, tls_codec::Deserialize as TlsDeserialize,
};
use openmls_traits::{
    signatures::{Signer as MlsSigner, SignerError},
    types::{Ciphersuite, SignatureScheme},
};

use crate::{SignKeypairPublic, SignKeypairSecret, SignedContent, sign, verify};

/// OpenMLS provider backed by libcrux.
pub type MlsProvider = openmls_libcrux_crypto::Provider;

/// The hybrid X-Wing MLS ciphersuite Facet uses for group transport.
pub const FACET_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// Draft wire code point for [`FACET_MLS_CIPHERSUITE`].
///
/// This is a draft MLS PQ ciphersuite value, so future OpenMLS/IETF versions
/// may require a wire-format migration if the final code point changes.
pub const FACET_MLS_CIPHERSUITE_CODEPOINT: u16 = 0x004D;

/// Messages created while adding a member.
///
/// `commit` is for the existing members. `welcome` is for the new member. Both
/// are serialized OpenMLS messages that a Delivery Service can relay opaquely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberMessages {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

impl MlsSigner for SignKeypairSecret {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        Ok(self.ed25519.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Create the libcrux-backed provider and assert that it supports Facet's
/// X-Wing ciphersuite.
pub fn new_provider() -> Result<MlsProvider> {
    let provider = MlsProvider::new()
        .map_err(|err| anyhow!("failed to create OpenMLS libcrux provider: {err:?}"))?;
    ensure_xwing_supported(&provider)?;
    Ok(provider)
}

/// Check whether a provider supports Facet's MLS ciphersuite.
pub fn ensure_xwing_supported(provider: &MlsProvider) -> Result<()> {
    provider
        .crypto()
        .supports(FACET_MLS_CIPHERSUITE)
        .map_err(|err| anyhow!("OpenMLS provider does not support Facet X-Wing suite: {err:?}"))
}

/// Build the MLS credential that binds an application identity to the Ed25519
/// half of a bilattice signing key.
pub fn credential(
    identity: impl Into<Vec<u8>>,
    signing_public: &SignKeypairPublic,
) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.into()).into(),
        signature_key: signing_public.ed25519.to_bytes().to_vec().into(),
    }
}

/// Default create config for Facet groups.
///
/// The ratchet tree extension is enabled so a Welcome can be processed from
/// the Welcome bytes alone, without a separate tree side channel.
pub fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(FACET_MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Join config matching [`group_create_config`].
pub fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

/// Create a one-member MLS group.
pub fn create_group(
    provider: &MlsProvider,
    signer: &SignKeypairSecret,
    group_id: impl AsRef<[u8]>,
    credential: CredentialWithKey,
) -> Result<MlsGroup> {
    ensure_xwing_supported(provider)?;
    MlsGroup::new_with_group_id(
        provider,
        signer,
        &group_create_config(),
        GroupId::from_slice(group_id.as_ref()),
        credential,
    )
    .map_err(|err| anyhow!("failed to create OpenMLS group: {err:?}"))
}

/// Generate a one-use KeyPackage for asynchronous group adds.
pub fn key_package(
    provider: &MlsProvider,
    signer: &SignKeypairSecret,
    credential: CredentialWithKey,
) -> Result<KeyPackageBundle> {
    ensure_xwing_supported(provider)?;
    KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(FACET_MLS_CIPHERSUITE, provider, signer, credential)
        .map_err(|err| anyhow!("failed to create OpenMLS KeyPackage: {err:?}"))
}

/// Add one member to a group, merge the local pending commit, and return the
/// serialized commit/welcome messages for delivery.
pub fn add_member(
    group: &mut MlsGroup,
    provider: &MlsProvider,
    signer: &SignKeypairSecret,
    key_package: &KeyPackage,
) -> Result<AddMemberMessages> {
    let (commit, welcome, _group_info) = group
        .add_members(provider, signer, std::slice::from_ref(key_package))
        .map_err(|err| anyhow!("failed to add OpenMLS member: {err:?}"))?;

    group
        .merge_pending_commit(provider)
        .map_err(|err| anyhow!("failed to merge OpenMLS add commit: {err:?}"))?;

    Ok(AddMemberMessages {
        commit: serialize_message(&commit)?,
        welcome: serialize_message(&welcome)?,
    })
}

/// Join a group from serialized Welcome bytes.
pub fn join_group_from_welcome(provider: &MlsProvider, welcome: &[u8]) -> Result<MlsGroup> {
    let message = deserialize_message(welcome)?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => anyhow::bail!("serialized OpenMLS message is not a Welcome"),
    };

    StagedWelcome::new_from_welcome(provider, &group_join_config(), welcome, None)
        .map_err(|err| anyhow!("failed to stage OpenMLS Welcome: {err:?}"))?
        .into_group(provider)
        .map_err(|err| anyhow!("failed to join OpenMLS group: {err:?}"))
}

/// Serialize an OpenMLS outbound message.
pub fn serialize_message(message: &MlsMessageOut) -> Result<Vec<u8>> {
    message
        .to_bytes()
        .map_err(|err| anyhow!("failed to serialize OpenMLS message: {err:?}"))
}

/// Deserialize a network MLS message.
pub fn deserialize_message(bytes: &[u8]) -> Result<MlsMessageIn> {
    let mut reader = bytes;
    MlsMessageIn::tls_deserialize(&mut reader)
        .map_err(|err| anyhow!("failed to deserialize OpenMLS message: {err:?}"))
}

/// Serialize a bilattice [`SignedContent`] for use as an MLS application
/// payload.
pub fn serialize_signed_content(signed: &SignedContent) -> Result<Vec<u8>> {
    postcard::to_allocvec(signed).context("failed to serialize SignedContent")
}

/// Deserialize a bilattice [`SignedContent`] from an MLS application payload.
pub fn deserialize_signed_content(payload: &[u8]) -> Result<SignedContent> {
    postcard::from_bytes(payload).context("failed to deserialize SignedContent")
}

/// Sign plaintext with bilattice, serialize the [`SignedContent`], then encrypt
/// it as an MLS application message.
pub fn create_signed_application_message(
    group: &mut MlsGroup,
    provider: &MlsProvider,
    mls_signer: &SignKeypairSecret,
    content_signer: &SignKeypairSecret,
    plaintext: Vec<u8>,
) -> Result<MlsMessageOut> {
    let signed = sign(plaintext, content_signer)?;
    let payload = serialize_signed_content(&signed)?;
    group
        .create_message(provider, mls_signer, &payload)
        .map_err(|err| anyhow!("failed to create OpenMLS application message: {err:?}"))
}

/// Process an incoming MLS message, extract a bilattice [`SignedContent`], and
/// require both bilattice signature layers to verify.
pub fn process_signed_application_message(
    group: &mut MlsGroup,
    provider: &MlsProvider,
    serialized_message: &[u8],
    sender_signing_public: &SignKeypairPublic,
) -> Result<SignedContent> {
    let message = deserialize_message(serialized_message)?
        .try_into_protocol_message()
        .map_err(|err| anyhow!("OpenMLS message is not a protocol message: {err:?}"))?;

    let processed = group
        .process_message(provider, message)
        .map_err(|err| anyhow!("failed to process OpenMLS message: {err:?}"))?;

    let payload = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => application.into_bytes(),
        other => anyhow::bail!("OpenMLS message is not application data: {other:?}"),
    };

    let signed = deserialize_signed_content(&payload)?;
    verify(&signed, sender_signing_public)
        .map_err(|layers| anyhow!("bilattice signature verification failed: {layers:?}"))?;
    Ok(signed)
}

/// Validate the X-Wing code point we compile against.
pub fn xwing_codepoint_is_expected() -> bool {
    u16::from(FACET_MLS_CIPHERSUITE) == FACET_MLS_CIPHERSUITE_CODEPOINT
}

/// Protocol version currently used by OpenMLS for serialized messages.
pub fn protocol_version() -> ProtocolVersion {
    ProtocolVersion::Mls10
}
