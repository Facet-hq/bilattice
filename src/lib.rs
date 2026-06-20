#![deny(unsafe_code)]

//! # bilattice
//!
//! Hybrid post-quantum cryptographic primitives for native secure messaging
//! apps. Every operation runs a classical and a post-quantum algorithm side by
//! side, so a break in one leaves the other standing.
//!
//! - `bi` — two algorithms per operation (classical + post-quantum).
//! - `lattice` — ML-KEM / ML-DSA are lattice-based.
//!
//! | Operation     | Classical | Post-quantum | Combiner / AEAD                    |
//! |---------------|-----------|--------------|-----------------------------------|
//! | KEM / encrypt | X25519    | ML-KEM-768   | HKDF-SHA3-256 → ChaCha20-Poly1305 |
//! | Signature     | Ed25519   | ML-DSA-65    | both must verify (AND)            |
//!
//! ## What this crate gives you (and what it doesn't)
//!
//! bilattice is a thin primitive layer. It hands you a small set of building
//! blocks:
//!
//! - [`generate_keypair`] — one identity = one encryption keypair + one signing
//!   keypair.
//! - [`encrypt_1_to_1`] / [`decrypt_1_to_1`] — confidentiality for a single
//!   message to a single recipient.
//! - [`sign`] / [`verify`] — authenticity for a blob of bytes.
//! - `validate` / `fingerprint` on the public-key bundles — sanity-check a key
//!   received from an untrusted source, and derive a stable SHA3-256 fingerprint
//!   for out-of-band verification.
//!
//! It deliberately does **not** provide:
//!
//! - **1-to-1 sessions / ratcheting.** Every [`encrypt_1_to_1`] call is a fresh,
//!   independent "sealed envelope": a new ephemeral X25519 key and a new ML-KEM
//!   encapsulation per message. There is no forward-secret session state here.
//!   Group/session protocols belong to the layer above this crate.
//! - **Identity binding.** Encryption and signing are separate operations on
//!   separate keys (see below). bilattice never automatically signs what it
//!   encrypts. Your app decides how to combine them.
//! - **A Delivery Service / federation.** The server side should just store and
//!   relay opaque bytes; queues, policy and federation belong above this crate.
//!
//! ## Combining encryption and signatures
//!
//! [`encrypt_1_to_1`] gives confidentiality and integrity of the ciphertext,
//! but it does **not** authenticate the *sender* — the recipient's public key
//! is enough to produce a valid ciphertext, so anyone could craft one. To prove
//! who sent a message, combine the two primitives. The recommended order for a
//! messaging app is **sign-then-encrypt**:
//!
//! ```no_run
//! # use bilattice::*;
//! # fn demo() -> anyhow::Result<()> {
//! let (enc_recipient, _) = generate_keypair()?;     // recipient's public keys
//! let (_, sig_sender) = generate_keypair()?;        // sender's signing keys
//!
//! // 1. sender signs the plaintext with their own signing key
//! let signed = sign(b"hello".to_vec(), &sig_sender.kp_sec)?;
//! // 2. serialize the signed blob, then encrypt it to the recipient
//! let bytes = bincode_or_serde(&signed);            // your serializer of choice
//! let envelope = encrypt_1_to_1(bytes, &enc_recipient.kp_pub)?;
//! # let _ = envelope; Ok(())
//! # }
//! # fn bincode_or_serde(_: &SignedContent) -> Vec<u8> { Vec::new() }
//! ```
//!
//! Sign-then-encrypt keeps the signature *inside* the encrypted envelope, so the
//! transport server (which must never see plaintext) also never sees who signed
//! what.
//!
//! ## Serialization & wire format
//!
//! Every public type derives [`serde::Serialize`] / [`serde::Deserialize`], so
//! you can move keys, signed blobs and [`EncryptedMessage`]s straight onto the
//! wire or into Postgres with whatever serde-compatible codec you prefer.
//! [`EncryptedMessage`] carries an explicit [`ENCRYPTED_MESSAGE_VERSION`] byte;
//! [`decrypt_1_to_1`] rejects anything it doesn't recognize, so the format can
//! evolve without silently misinterpreting old ciphertexts.

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{SigningKey as Ed25519Sec, VerifyingKey as Ed25519Pub};
use hkdf::Hkdf;
use oqs::kem;
use oqs::kem::{PublicKey as KyberPub, SecretKey as KyberSec};
use oqs::sig;
use oqs::sig::{PublicKey as DilithiumPub, SecretKey as DilithiumSec};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{
    EphemeralSecret as X25519EphSec, PublicKey as X25519Pub, StaticSecret as X25519Sec,
};
use zeroize::Zeroizing;

const DSA_ALGORITHM: sig::Algorithm = sig::Algorithm::MlDsa65;
const KEM_ALGORITHM: kem::Algorithm = kem::Algorithm::MlKem768;

/// Wire-format version stamped into every [`EncryptedMessage`].
///
/// [`decrypt_1_to_1`] refuses any message whose `version` differs, so bumping
/// this constant is how the on-the-wire format evolves without old and new
/// clients silently misreading each other.
pub const ENCRYPTED_MESSAGE_VERSION: u8 = 2;

/// Number of bytes in a public-key fingerprint.
pub const KEY_FINGERPRINT_LEN: usize = 32;

/// SHA3-256 fingerprint of a public keypair.
pub type KeyFingerprint = [u8; KEY_FINGERPRINT_LEN];

const HKDF_SALT: &[u8] = b"Facet's bilattice v1 lib";
const MESSAGE_DIRECTION: &[u8] = b"1to1 message sender->recipient";
const AEAD_INFO_LABEL: &[u8] = b"chacha20poly1305 key";
const ED25519_CONTENT_SIGNATURE_DOMAIN: &[u8] = b"facet-bilattice-v1 ed25519 content signature";
const ML_DSA_CONTENT_SIGNATURE_CONTEXT: &[u8] = b"facet-bilattice-v1 ml-dsa-65 content";
const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const KDF_OUTPUT_LEN: usize = AEAD_KEY_LEN + AEAD_NONCE_LEN;
// Public, fixed scalar used only to reject non-contributory X25519 inputs.
// It is not used to derive message keys, so it does not need to be secret.
const X25519_CONTRIBUTORY_CHECK_SCALAR: [u8; 32] = [0x42; 32];

/// A hybrid keypair used to **receive** encrypted messages.
///
/// Bundles both halves (public + secret) of the X25519 and ML-KEM-768 keys.
/// Hand the [`kp_pub`](Self::kp_pub) to senders (publish it on your identity
/// server); keep the whole struct private to decrypt with
/// [`decrypt_1_to_1`].
#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypair {
    pub kp_pub: EncryptionKeypairPublic,
    pub kp_sec: EncryptionKeypairSecret,
}

/// Public encryption keys for one identity — this is what a sender needs.
///
/// Safe to publish. Pass a reference to [`encrypt_1_to_1`] to seal a message
/// that only the matching [`EncryptionKeypairSecret`] can open.
#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypairPublic {
    pub kyber: KyberPub,
    pub x25519: X25519Pub,
}

impl EncryptionKeypairPublic {
    /// Reconstruct public encryption keys from raw wire/storage bytes.
    ///
    /// This keeps algorithm selection inside bilattice: ML-KEM-768 is the only
    /// KEM used here, via the crate's fixed algorithm constant.
    pub fn from_bytes(kyber: &[u8], x25519: &[u8]) -> Result<Self> {
        oqs::init();

        let kem_alg = kem::Kem::new(KEM_ALGORITHM)?;
        let kyber = kem_alg
            .public_key_from_bytes(kyber)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM public key"))?
            .to_owned();
        let x25519: [u8; 32] = x25519.try_into().map_err(|_| {
            anyhow::anyhow!(
                "invalid X25519 public key length: expected 32, got {}",
                x25519.len()
            )
        })?;

        let public = Self {
            kyber,
            x25519: X25519Pub::from(x25519),
        };
        public.validate()?;
        Ok(public)
    }

    /// Validate this public encryption key bundle before accepting it from an
    /// untrusted source.
    ///
    /// This checks the ML-KEM-768 public-key length expected by liboqs and
    /// rejects non-contributory X25519 public keys (for example the all-zero
    /// low-order point). It does **not** prove ownership of the matching secret
    /// keys; bind the bundle to an identity with a signed challenge at the
    /// protocol layer.
    pub fn validate(&self) -> Result<()> {
        oqs::init();

        let kem_alg = kem::Kem::new(KEM_ALGORITHM)?;
        if self.kyber.as_ref().len() != kem_alg.length_public_key() {
            anyhow::bail!(
                "invalid ML-KEM public key length: expected {}, got {}",
                kem_alg.length_public_key(),
                self.kyber.as_ref().len()
            );
        }

        validate_x25519_public_key(&self.x25519)?;
        Ok(())
    }

    /// Return a stable SHA3-256 fingerprint for these public encryption keys.
    pub fn fingerprint(&self) -> KeyFingerprint {
        let mut h = Sha3_256::new();
        h.update(b"facet-bilattice-v1 encryption-public-key fingerprint");
        h.update(b"x25519");
        h.update(self.x25519.as_bytes());
        h.update(b"ml-kem-768");
        h.update(self.kyber.as_ref());
        h.finalize().into()
    }

    /// Return the public encryption key fingerprint as lowercase hex.
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint())
    }
}

/// Secret encryption keys for one identity — **never leaves the device**.
///
/// Required to [`decrypt_1_to_1`]. Treat as highly sensitive; do not log,
/// serialize to the server, or transmit.
#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypairSecret {
    pub kyber: MlKemSecretKey,
    pub x25519: X25519Sec,
}

// ------

/// A hybrid keypair used to **sign** messages and prove sender identity.
///
/// Bundles both halves of the Ed25519 and ML-DSA-65 keys. Distinct from
/// [`EncryptionKeypair`]: encryption and signing use separate keys, and
/// [`generate_keypair`] mints both at once for a single identity.
#[derive(Serialize, Deserialize)]
pub struct SignKeypair {
    pub kp_pub: SignKeypairPublic,
    pub kp_sec: SignKeypairSecret,
}

/// Public signing keys for one identity — publish these so others can
/// [`verify`] your signatures.
#[derive(Serialize, Deserialize)]
pub struct SignKeypairPublic {
    pub dilithium: DilithiumPub,
    pub ed25519: Ed25519Pub,
}

impl SignKeypairPublic {
    /// Reconstruct public signing keys from raw wire/storage bytes.
    ///
    /// This keeps algorithm selection inside bilattice: ML-DSA-65 is the only
    /// post-quantum signature algorithm used here, via the crate's fixed
    /// algorithm constant.
    pub fn from_bytes(dilithium: &[u8], ed25519: &[u8]) -> Result<Self> {
        oqs::init();

        let sig_alg = sig::Sig::new(DSA_ALGORITHM)?;
        let dilithium = sig_alg
            .public_key_from_bytes(dilithium)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA public key"))?
            .to_owned();
        let ed25519: [u8; 32] = ed25519.try_into().map_err(|_| {
            anyhow::anyhow!(
                "invalid Ed25519 public key length: expected 32, got {}",
                ed25519.len()
            )
        })?;
        let ed25519 = Ed25519Pub::from_bytes(&ed25519)
            .map_err(|error| anyhow::anyhow!("invalid Ed25519 public key: {}", error))?;

        let public = Self { dilithium, ed25519 };
        public.validate()?;
        Ok(public)
    }

    /// Validate this public signing key bundle before accepting it from an
    /// untrusted source.
    ///
    /// This checks the ML-DSA-65 public-key length expected by liboqs and
    /// rejects weak / low-order Ed25519 keys. It does **not** prove ownership of
    /// the matching secret keys; verify a signed challenge or signed key bundle
    /// at the protocol layer.
    pub fn validate(&self) -> Result<()> {
        oqs::init();

        let sig_alg = sig::Sig::new(DSA_ALGORITHM)?;
        if self.dilithium.as_ref().len() != sig_alg.length_public_key() {
            anyhow::bail!(
                "invalid ML-DSA public key length: expected {}, got {}",
                sig_alg.length_public_key(),
                self.dilithium.as_ref().len()
            );
        }

        if self.ed25519.is_weak() {
            anyhow::bail!("weak Ed25519 public key");
        }

        Ok(())
    }

    /// Return a stable SHA3-256 fingerprint for these public signing keys.
    pub fn fingerprint(&self) -> KeyFingerprint {
        let mut h = Sha3_256::new();
        h.update(b"facet-bilattice-v1 signing-public-key fingerprint");
        h.update(b"ed25519");
        h.update(self.ed25519.as_bytes());
        h.update(b"ml-dsa-65");
        h.update(self.dilithium.as_ref());
        h.finalize().into()
    }

    /// Return the public signing key fingerprint as lowercase hex.
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint())
    }
}

/// Secret signing keys for one identity — **never leaves the device**.
///
/// Required to [`sign`]. Treat as highly sensitive.
#[derive(Serialize, Deserialize)]
pub struct SignKeypairSecret {
    pub dilithium: MlDsaSecretKey,
    pub ed25519: Ed25519Sec,
}

/// Owned ML-KEM-768 secret key bytes, zeroized on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct MlKemSecretKey(Zeroizing<Vec<u8>>);

impl MlKemSecretKey {
    fn from_oqs(secret_key: KyberSec) -> Self {
        Self(Zeroizing::new(secret_key.into_vec()))
    }

    fn as_oqs_ref<'a>(&'a self, kem_alg: &kem::Kem) -> Result<kem::SecretKeyRef<'a>> {
        kem_alg
            .secret_key_from_bytes(self.0.as_slice())
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM secret key length"))
    }

    /// Return the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for MlKemSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Owned ML-DSA-65 secret key bytes, zeroized on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct MlDsaSecretKey(Zeroizing<Vec<u8>>);

impl MlDsaSecretKey {
    fn from_oqs(secret_key: DilithiumSec) -> Self {
        Self(Zeroizing::new(secret_key.into_vec()))
    }

    fn as_oqs_ref<'a>(&'a self, sig_alg: &sig::Sig) -> Result<sig::SecretKeyRef<'a>> {
        sig_alg
            .secret_key_from_bytes(self.0.as_slice())
            .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA secret key length"))
    }

    /// Return the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for MlDsaSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// ---

/// Owned ML-DSA-65 signature bytes.
///
/// This keeps `oqs` out of the public client API for signature reconstruction:
/// clients can persist / receive raw bytes and rebuild the signature with
/// [`MlDsaSignature::from_bytes`] instead of calling `oqs::sig` directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaSignature(Vec<u8>);

impl MlDsaSignature {
    fn from_oqs(signature: sig::Signature) -> Self {
        Self(signature.into_vec())
    }

    /// Reconstruct an ML-DSA-65 signature from raw bytes.
    ///
    /// This initializes liboqs and validates the byte length against the
    /// crate's fixed ML-DSA algorithm. It does not prove authenticity; use
    /// [`verify`] for that.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        oqs::init();

        let sig_alg = sig::Sig::new(DSA_ALGORITHM)?;
        let expected_len = sig_alg.length_signature();
        if bytes.len() != expected_len {
            anyhow::bail!(
                "invalid ML-DSA signature length: expected {}, got {}",
                expected_len,
                bytes.len()
            );
        }

        Ok(Self(bytes))
    }

    fn as_oqs_ref<'a>(&'a self, sig_alg: &sig::Sig) -> Result<sig::SignatureRef<'a>> {
        let expected_len = sig_alg.length_signature();
        if self.0.len() != expected_len {
            anyhow::bail!(
                "invalid ML-DSA signature length: expected {}, got {}",
                expected_len,
                self.0.len()
            );
        }

        sig_alg
            .signature_from_bytes(self.0.as_slice())
            .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA signature length"))
    }

    /// Return the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consume this signature and return the raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for MlDsaSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The two signatures that must travel and verify together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    pub dilithium: MlDsaSignature,
    pub ed25519: ed25519_dalek::Signature,
}

impl HybridSignature {
    /// Reconstruct a hybrid signature from raw signature bytes.
    ///
    /// `dilithium` is ML-DSA-65/Dilithium bytes. `ed25519` must be exactly 64
    /// bytes. Use [`verify`] afterward to authenticate content.
    pub fn from_bytes(dilithium: Vec<u8>, ed25519: &[u8]) -> Result<Self> {
        let ed25519: [u8; ed25519_dalek::SIGNATURE_LENGTH] = ed25519.try_into().map_err(|_| {
            anyhow::anyhow!(
                "invalid Ed25519 signature length: expected {}, got {}",
                ed25519_dalek::SIGNATURE_LENGTH,
                ed25519.len()
            )
        })?;

        Ok(Self {
            dilithium: MlDsaSignature::from_bytes(dilithium)?,
            ed25519: ed25519_dalek::Signature::from_bytes(&ed25519),
        })
    }

    /// Build from already reconstructed per-algorithm signatures.
    pub fn from_parts(dilithium: MlDsaSignature, ed25519: ed25519_dalek::Signature) -> Self {
        Self { dilithium, ed25519 }
    }

    /// Return the raw ML-DSA-65 signature bytes.
    pub fn dilithium_bytes(&self) -> &[u8] {
        self.dilithium.as_bytes()
    }

    /// Return the raw Ed25519 signature bytes.
    pub fn ed25519_bytes(&self) -> [u8; ed25519_dalek::SIGNATURE_LENGTH] {
        self.ed25519.to_bytes()
    }
}

/// A blob plus its hybrid signature, the output of [`sign`].
///
/// Holds the original `content` alongside an Ed25519 + ML-DSA-65 signature pair
/// over those exact bytes. Pass it to [`verify`], which requires **both**
/// signatures to validate. Serializable, so you can ship the whole thing over
/// the wire (or, for sign-then-encrypt, feed it into [`encrypt_1_to_1`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContent {
    pub content: Vec<u8>,
    pub signature: HybridSignature,
}

/// A sealed 1-to-1 message: the output of [`encrypt_1_to_1`], the input to
/// [`decrypt_1_to_1`].
///
/// Self-contained — everything the recipient needs to reconstruct the AEAD key
/// travels with it:
///
/// - `version` — wire format, checked against [`ENCRYPTED_MESSAGE_VERSION`].
/// - `x25519_ephemeral_pub` — the per-message ephemeral public key (the classical
///   half of the KEM).
/// - `ml_kem_ciphertext` — the ML-KEM-768 encapsulation (the post-quantum half).
/// - `ciphertext` — the ChaCha20-Poly1305 sealed payload.
///
/// The AEAD nonce is *derived*, not stored, so it is not a public field. Safe to
/// hand to an untrusted transport server: it reveals neither plaintext nor
/// sender identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub version: u8,
    pub x25519_ephemeral_pub: x25519_dalek::PublicKey,
    pub ml_kem_ciphertext: kem::Ciphertext,
    pub ciphertext: Vec<u8>,
}

/// Per-algorithm failure detail returned by [`verify`].
///
/// Each field is `Some(reason)` when that algorithm's check failed, `None` when
/// it passed. A whole `LayerErrors` is only produced when at least one layer
/// failed — verification succeeds only when **both** are `None`. Inspect the
/// fields to tell apart "the post-quantum signature is bad" from "the classical
/// one is".
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerErrors {
    pub dilithium: Option<String>,
    pub ed25519: Option<String>,
}

fn hybrid_ikm(x25519_ss: &[u8; 32], ml_kem_ss: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    if ml_kem_ss.len() != 32 {
        anyhow::bail!(
            "unexpected ML-KEM shared secret length: {}",
            ml_kem_ss.len()
        );
    }

    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(ml_kem_ss);
    Ok(ikm)
}

fn transcript_hash(
    x25519_ephemeral_pub: &X25519Pub,
    recipient: &EncryptionKeypairPublic,
    ml_kem_ciphertext: &[u8],
) -> [u8; 32] {
    let mut h = Sha3_256::new();

    h.update(b"facet-bilattice-v1 transcript");
    h.update(b"alg:x25519+ml-kem+hkdf-sha3-256+chacha20poly1305");

    h.update(b"x25519_ephemeral_pub");
    h.update(x25519_ephemeral_pub.as_bytes());

    h.update(b"recipient_x25519_pub");
    h.update(recipient.x25519.as_bytes());

    h.update(b"recipient_kyber_pub");
    h.update(recipient.kyber.as_ref());

    h.update(b"kyber_ciphertext");
    h.update(ml_kem_ciphertext);

    h.finalize().into()
}

fn derive_aead_key_material(
    ikm: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; KDF_OUTPUT_LEN]>> {
    let hk = Hkdf::<Sha3_256>::new(Some(HKDF_SALT), ikm);

    let mut info = Vec::new();
    info.extend_from_slice(AEAD_INFO_LABEL);
    info.extend_from_slice(b"\0");
    info.extend_from_slice(transcript_hash);
    info.extend_from_slice(b"\0");
    info.extend_from_slice(MESSAGE_DIRECTION);

    let mut out = Zeroizing::new([0u8; KDF_OUTPUT_LEN]);
    hk.expand(&info, &mut out[..])
        .map_err(|err| anyhow::anyhow!("HKDF-SHA3 expand failed: {}", err))?;
    Ok(out)
}

fn chacha20poly1305_from_key(key: &[u8]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid ChaCha20Poly1305 key length"))
}

fn ed25519_content_signature_message(content: &[u8]) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(ED25519_CONTENT_SIGNATURE_DOMAIN.len() + 1 + 8 + content.len());
    msg.extend_from_slice(ED25519_CONTENT_SIGNATURE_DOMAIN);
    msg.push(0);
    msg.extend_from_slice(&(content.len() as u64).to_be_bytes());
    msg.extend_from_slice(content);
    msg
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_x25519_public_key(public_key: &X25519Pub) -> Result<()> {
    let validation_scalar = X25519Sec::from(X25519_CONTRIBUTORY_CHECK_SCALAR);
    let shared_secret = validation_scalar.diffie_hellman(public_key);

    if !shared_secret.was_contributory() {
        anyhow::bail!("non-contributory X25519 public key");
    }

    Ok(())
}

/// Mint a fresh identity: one [`EncryptionKeypair`] and one [`SignKeypair`].
///
/// A messaging app calls this once per device/identity at registration. The two
/// keypairs are independent — encryption uses X25519 + ML-KEM-768, signing uses
/// Ed25519 + ML-DSA-65 — but they belong to the same logical identity, so they
/// are generated together. Publish both *public* halves
/// ([`EncryptionKeypairPublic`], [`SignKeypairPublic`]) to your identity server;
/// keep the secret halves on the device.
///
/// Randomness comes from the OS CSPRNG ([`OsRng`]).
///
/// ```no_run
/// # use bilattice::generate_keypair;
/// let (encryption, signing) = generate_keypair()?;
/// // share these:
/// let _enc_pub = &encryption.kp_pub;
/// let _sig_pub = &signing.kp_pub;
/// # Ok::<(), anyhow::Error>(())
/// ```
///
/// # Errors
/// Returns an error if the underlying liboqs KEM/signature initialization fails.
pub fn generate_keypair() -> Result<(EncryptionKeypair, SignKeypair)> {
    oqs::init();

    let mut rng = OsRng;

    let kem_alg = kem::Kem::new(KEM_ALGORITHM)?;
    let (kyber, kyber_secret) = kem_alg.keypair()?;

    let sig_alg = sig::Sig::new(DSA_ALGORITHM)?;
    let (dilithium, dilithium_secret) = sig_alg.keypair()?;

    let x25519 = X25519Sec::random();
    let x25519_public = X25519Pub::from(&x25519);

    let ed25519 = Ed25519Sec::generate(&mut rng);
    let ed25519_public = ed25519.verifying_key();

    Ok((
        EncryptionKeypair {
            kp_pub: EncryptionKeypairPublic {
                kyber,
                x25519: x25519_public,
            },
            kp_sec: EncryptionKeypairSecret {
                kyber: MlKemSecretKey::from_oqs(kyber_secret),
                x25519,
            },
        },
        SignKeypair {
            kp_pub: SignKeypairPublic {
                dilithium,
                ed25519: ed25519_public,
            },
            kp_sec: SignKeypairSecret {
                dilithium: MlDsaSecretKey::from_oqs(dilithium_secret),
                ed25519,
            },
        },
    ))
}

/// Sign `content` with both halves of the sender's signing key.
///
/// Produces a [`SignedContent`] holding the original bytes plus an Ed25519 and
/// an ML-DSA-65 signature over a domain-separated bilattice content-signature
/// context. Use this to prove *who* sent a message; pair it with [`verify`] on
/// the receiving side. For a messaging app, the usual flow is sign-then-encrypt:
/// sign the plaintext, serialize the
/// [`SignedContent`], then [`encrypt_1_to_1`] the result so the signature stays
/// hidden from the transport server.
///
/// # Errors
/// Returns an error if liboqs fails to initialize or to produce the ML-DSA
/// signature.
pub fn sign(content: Vec<u8>, sender: &SignKeypairSecret) -> Result<SignedContent> {
    oqs::init();
    let ed25519_message = ed25519_content_signature_message(&content);
    let sig_alg = sig::Sig::new(DSA_ALGORITHM)?;
    let dilithium = sender.dilithium.as_oqs_ref(&sig_alg)?;
    Ok(SignedContent {
        signature: HybridSignature {
            dilithium: MlDsaSignature::from_oqs(sig_alg.sign_with_ctx_str(
                &content,
                ML_DSA_CONTENT_SIGNATURE_CONTEXT,
                dilithium,
            )?),
            ed25519: sender.ed25519.sign(&ed25519_message),
        },
        content,
    })
}

/// Verify a [`SignedContent`] against the sender's public signing keys.
///
/// **Both** signatures must validate (logical AND): if either the Ed25519 or the
/// ML-DSA-65 check fails, the whole verification fails. This is what makes the
/// scheme hybrid-secure — a forgery has to break *both* algorithms at once.
///
/// Returns `Ok(())` only when both layers pass. On any failure it returns a
/// [`LayerErrors`] whose fields tell you exactly which layer(s) rejected the
/// signature and why.
///
/// ```no_run
/// # use bilattice::{generate_keypair, sign, verify};
/// # fn demo() -> anyhow::Result<()> {
/// let (_, signing) = generate_keypair()?;
/// let signed = sign(b"hi".to_vec(), &signing.kp_sec)?;
/// match verify(&signed, &signing.kp_pub) {
///     Ok(()) => { /* authentic */ }
///     Err(layers) => {
///         eprintln!("dilithium: {:?}, ed25519: {:?}", layers.dilithium, layers.ed25519);
///     }
/// }
/// # Ok(()) }
/// ```
///
/// The Ed25519 check uses `verify_strict` to reject malleable / non-canonical
/// signatures.
pub fn verify(
    sigcontent: &SignedContent,
    sender: &SignKeypairPublic,
) -> std::result::Result<(), LayerErrors> {
    oqs::init();
    let dilithium_err = match sig::Sig::new(DSA_ALGORITHM) {
        Ok(sig_alg) => match sigcontent.signature.dilithium.as_oqs_ref(&sig_alg) {
            Ok(dilithium_signature) => sig_alg
                .verify_with_ctx_str(
                    &sigcontent.content,
                    dilithium_signature,
                    ML_DSA_CONTENT_SIGNATURE_CONTEXT,
                    &sender.dilithium,
                )
                .err()
                .map(|e| e.to_string()),
            Err(err) => Some(err.to_string()),
        },
        Err(err) => Some(err.to_string()),
    };

    let ed25519_message = ed25519_content_signature_message(&sigcontent.content);
    let ed25519_err = sender
        .ed25519
        .verify_strict(&ed25519_message, &sigcontent.signature.ed25519)
        .err()
        .map(|e| e.to_string());

    if dilithium_err.is_none() && ed25519_err.is_none() {
        Ok(())
    } else {
        Err(LayerErrors {
            dilithium: dilithium_err,
            ed25519: ed25519_err,
        })
    }
}

/// Seal `content` for a single recipient, identified by their public
/// encryption keys.
///
/// Each call is a standalone "sealed envelope": it [`validate`](EncryptionKeypairPublic::validate)s
/// the recipient's public keys, generates a fresh ephemeral X25519 key and a
/// fresh ML-KEM-768 encapsulation, derives the two shared secrets, combines them
/// with HKDF-SHA3-256, and encrypts with ChaCha20-Poly1305. Because both KEMs
/// contribute to the key, an attacker must break *both* X25519 and ML-KEM to
/// recover the plaintext.
///
/// The result is a self-contained [`EncryptedMessage`] safe to store on or relay
/// through an untrusted server — it leaks neither the plaintext nor the sender.
///
/// ## What this does and doesn't guarantee
///
/// - **Confidentiality + integrity** of the payload: yes, only the holder of the
///   matching [`EncryptionKeypairSecret`] can decrypt, and tampering is detected.
/// - **Sender authentication**: *no*. Anyone with the recipient's public key can
///   produce a valid envelope. If the recipient must know who sent it, [`sign`]
///   the plaintext first and encrypt the [`SignedContent`] (sign-then-encrypt).
/// - **Forward secrecy across messages**: not provided here. Each message is
///   independent; ratcheting belongs to the session layer above.
///
/// ```no_run
/// # use bilattice::{generate_keypair, encrypt_1_to_1};
/// # fn demo() -> anyhow::Result<()> {
/// let (recipient, _) = generate_keypair()?;
/// let envelope = encrypt_1_to_1(b"hello".to_vec(), &recipient.kp_pub)?;
/// # let _ = envelope; Ok(()) }
/// ```
///
/// # Errors
/// Returns an error if ML-KEM encapsulation, HKDF expansion, or AEAD encryption
/// fails.
pub fn encrypt_1_to_1(
    content: Vec<u8>,
    recipient: &EncryptionKeypairPublic,
) -> Result<EncryptedMessage> {
    oqs::init();
    recipient.validate()?;

    let (kyber_ct, kyber_ss) = kem::Kem::new(KEM_ALGORITHM)?
        .encapsulate(&recipient.kyber)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with public key: {}", e))?;
    let kyber_ss = Zeroizing::new(kyber_ss.into_vec());
    let x25519_ephemeral = X25519EphSec::random();
    let x25519_ephemeral_pub = X25519Pub::from(&x25519_ephemeral);
    let x25519_ss = x25519_ephemeral.diffie_hellman(&recipient.x25519);

    let ikm = hybrid_ikm(x25519_ss.as_bytes(), kyber_ss.as_slice())?;
    let transcript_hash = transcript_hash(&x25519_ephemeral_pub, recipient, kyber_ct.as_ref());
    let out = derive_aead_key_material(&ikm[..], &transcript_hash)?;
    let key = &out[..AEAD_KEY_LEN];
    let nonce_bytes = &out[AEAD_KEY_LEN..];
    let cipher = chacha20poly1305_from_key(key)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, content.as_ref())
        .map_err(|_| anyhow::anyhow!("ChaCha20Poly1305 encryption failed"))?;

    Ok(EncryptedMessage {
        version: ENCRYPTED_MESSAGE_VERSION,
        x25519_ephemeral_pub,
        ml_kem_ciphertext: kyber_ct,
        ciphertext,
    })
}

/// Open an [`EncryptedMessage`] sealed by [`encrypt_1_to_1`], recovering the
/// plaintext.
///
/// Needs the recipient's full [`EncryptionKeypair`] (both secret and public
/// halves — the public keys feed the transcript hash that binds the derived
/// key). Reconstructs the hybrid shared secret by decapsulating the ML-KEM
/// ciphertext and running X25519 against the embedded ephemeral key, then
/// re-derives the AEAD key and nonce and decrypts.
///
/// As defense in depth, it first rejects messages whose `version` differs from
/// [`ENCRYPTED_MESSAGE_VERSION`].
///
/// ```no_run
/// # use bilattice::{generate_keypair, encrypt_1_to_1, decrypt_1_to_1};
/// # fn demo() -> anyhow::Result<()> {
/// let (recipient, _) = generate_keypair()?;
/// let envelope = encrypt_1_to_1(b"hello".to_vec(), &recipient.kp_pub)?;
/// let plaintext = decrypt_1_to_1(envelope, &recipient)?;
/// assert_eq!(plaintext, b"hello");
/// # Ok(()) }
/// ```
///
/// # Errors
/// Returns an error if the version is unsupported, ML-KEM decapsulation fails,
/// or AEAD authentication/decryption fails (e.g. the message was tampered with
/// or sealed for a different recipient).
pub fn decrypt_1_to_1(
    encrypted_content: EncryptedMessage,
    recipient: &EncryptionKeypair,
) -> Result<Vec<u8>> {
    oqs::init();
    if encrypted_content.version != ENCRYPTED_MESSAGE_VERSION {
        anyhow::bail!(
            "unsupported encrypted message version: {}",
            encrypted_content.version
        );
    }

    let kem_alg = kem::Kem::new(KEM_ALGORITHM)?;
    let kyber = recipient.kp_sec.kyber.as_oqs_ref(&kem_alg)?;
    let kyber_ss = kem_alg.decapsulate(kyber, &encrypted_content.ml_kem_ciphertext)?;
    let kyber_ss = Zeroizing::new(kyber_ss.into_vec());
    let x25519_ss = recipient
        .kp_sec
        .x25519
        .diffie_hellman(&encrypted_content.x25519_ephemeral_pub);
    if !x25519_ss.was_contributory() {
        anyhow::bail!("non-contributory X25519 ephemeral public key");
    }

    let ikm = hybrid_ikm(x25519_ss.as_bytes(), kyber_ss.as_slice())?;
    let transcript_hash = transcript_hash(
        &encrypted_content.x25519_ephemeral_pub,
        &recipient.kp_pub,
        encrypted_content.ml_kem_ciphertext.as_ref(),
    );
    let out = derive_aead_key_material(&ikm[..], &transcript_hash)?;
    let key = &out[..AEAD_KEY_LEN];
    let nonce_bytes = &out[AEAD_KEY_LEN..];

    let cipher = chacha20poly1305_from_key(key)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, encrypted_content.ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("ChaCha20Poly1305 decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_public_key_bundles_validate() -> Result<()> {
        let (encryption, signing) = generate_keypair()?;

        encryption.kp_pub.validate()?;
        signing.kp_pub.validate()?;

        Ok(())
    }

    #[test]
    fn public_key_bundles_reconstruct_from_raw_bytes() -> Result<()> {
        let (encryption, signing) = generate_keypair()?;

        let rebuilt_encryption = EncryptionKeypairPublic::from_bytes(
            encryption.kp_pub.kyber.as_ref(),
            encryption.kp_pub.x25519.as_bytes(),
        )?;
        let rebuilt_signing = SignKeypairPublic::from_bytes(
            signing.kp_pub.dilithium.as_ref(),
            signing.kp_pub.ed25519.as_bytes(),
        )?;

        assert_eq!(
            rebuilt_encryption.fingerprint(),
            encryption.kp_pub.fingerprint()
        );
        assert_eq!(rebuilt_signing.fingerprint(), signing.kp_pub.fingerprint());
        Ok(())
    }

    #[test]
    fn signing_validation_rejects_weak_ed25519_public_key() -> Result<()> {
        let (_, signing) = generate_keypair()?;
        let mut weak_bytes = [0u8; 32];
        weak_bytes[0] = 1;
        let weak_ed25519 = Ed25519Pub::from_bytes(&weak_bytes)?;

        let invalid = SignKeypairPublic {
            dilithium: signing.kp_pub.dilithium,
            ed25519: weak_ed25519,
        };

        assert!(invalid.validate().is_err());
        Ok(())
    }

    #[test]
    fn encryption_validation_rejects_non_contributory_x25519_public_key() -> Result<()> {
        let (encryption, _) = generate_keypair()?;
        let invalid = EncryptionKeypairPublic {
            kyber: encryption.kp_pub.kyber,
            x25519: X25519Pub::from([0u8; 32]),
        };

        assert!(invalid.validate().is_err());
        Ok(())
    }

    #[test]
    fn decrypt_rejects_non_contributory_ephemeral_x25519_public_key() -> Result<()> {
        let (recipient, _) = generate_keypair()?;
        let mut envelope = encrypt_1_to_1(b"hello".to_vec(), &recipient.kp_pub)?;
        envelope.x25519_ephemeral_pub = X25519Pub::from([0u8; 32]);

        assert!(decrypt_1_to_1(envelope, &recipient).is_err());
        Ok(())
    }
}
