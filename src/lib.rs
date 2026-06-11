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
pub const ENCRYPTED_MESSAGE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypair {
    pub kp_pub: EncryptionKeypairPublic,
    pub kp_sec: EncryptionKeypairSecret,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypairPublic {
    pub kyber: KyberPub,
    pub x25519: X25519Pub,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionKeypairSecret {
    pub kyber: KyberSec,
    pub x25519: X25519Sec,
}

// ------

#[derive(Serialize, Deserialize)]
pub struct SignKeypair {
    pub kp_pub: SignKeypairPublic,
    pub kp_sec: SignKeypairSecret,
}

#[derive(Serialize, Deserialize)]
pub struct SignKeypairPublic {
    pub dilithium: DilithiumPub,
    pub ed25519: Ed25519Pub,
}

#[derive(Serialize, Deserialize)]
pub struct SignKeypairSecret {
    pub dilithium: DilithiumSec,
    pub ed25519: Ed25519Sec,
}

// ---

#[derive(Serialize, Deserialize)]
pub struct SignedContent {
    pub content: Vec<u8>,
    pub dilithium_sign: sig::Signature,
    pub ed25519_sign: ed25519_dalek::Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub version: u8,
    pub x25519_ephemeral_pub: x25519_dalek::PublicKey,
    poly1305_nonce: Vec<u8>,
    pub ml_kem_ciphertext: kem::Ciphertext,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LayerErrors {
    pub dilithium: Option<String>,
    pub ed25519: Option<String>,
}

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
                kyber: kyber_secret,
                x25519,
            },
        },
        SignKeypair {
            kp_pub: SignKeypairPublic {
                dilithium,
                ed25519: ed25519_public,
            },
            kp_sec: SignKeypairSecret {
                dilithium: dilithium_secret,
                ed25519,
            },
        },
    ))
}

pub fn sign(content: Vec<u8>, sender: &SignKeypairSecret) -> Result<SignedContent> {
    oqs::init();
    let array_content = &content.clone();
    Ok(SignedContent {
        content,
        dilithium_sign: { sig::Sig::new(DSA_ALGORITHM)?.sign(array_content, &sender.dilithium)? },
        ed25519_sign: { sender.ed25519.sign(array_content) },
    })
}

pub fn verify(
    sigcontent: &SignedContent,
    sender: &SignKeypairPublic,
) -> std::result::Result<(), LayerErrors> {
    oqs::init();
    let dilithium_err = match sig::Sig::new(DSA_ALGORITHM) {
        Ok(sig_alg) => sig_alg
            .verify(
                &sigcontent.content,
                &sigcontent.dilithium_sign,
                &sender.dilithium,
            )
            .err()
            .map(|e| e.to_string()),
        Err(err) => Some(err.to_string()),
    };

    let ed25519_err = sender
        .ed25519
        .verify_strict(&sigcontent.content, &sigcontent.ed25519_sign)
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

pub fn encrypt_1_to_1(
    content: Vec<u8>,
    recipient: &EncryptionKeypairPublic,
) -> Result<EncryptedMessage> {
    oqs::init();
    let salt = b"Facet's bilattice v1 lib";
    let direction = b"1to1 message sender->recipient";
    let mut ikm = Zeroizing::new([0u8; 64]);

    let (kyber_ct, kyber_ss) = kem::Kem::new(KEM_ALGORITHM)?
        .encapsulate(&recipient.kyber)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with public key: {}", e))?;
    let x25519_ephemeral = X25519EphSec::random();
    let x25519_ephemeral_pub = X25519Pub::from(&x25519_ephemeral);
    let x25519_ss = x25519_ephemeral.diffie_hellman(&recipient.x25519);

    ikm[..32].copy_from_slice(x25519_ss.as_bytes());
    ikm[32..].copy_from_slice(kyber_ss.as_ref());

    let transcript_hash = {
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
        h.update(kyber_ct.as_ref());

        let out: [u8; 32] = h.finalize().into();
        out
    };

    let hk = Hkdf::<Sha3_256>::new(Some(salt), &ikm[..]);

    let mut info = Vec::new();
    info.extend_from_slice(b"chacha20poly1305 key");
    info.extend_from_slice(b"\0");
    info.extend_from_slice(&transcript_hash);
    info.extend_from_slice(b"\0");
    info.extend_from_slice(direction);

    // 32 bytes key + 12 bytes nonce
    let mut out = Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut out[..])
        .map_err(|err| anyhow::anyhow!("HKDF-SHA3 expand failed: {}", err))?;
    let key = &out[..32];
    let nonce_bytes = &out[32..44];
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid ChaCha20Poly1305 key length"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, content.as_ref())
        .map_err(|_| anyhow::anyhow!("ChaCha20Poly1305 encryption failed"))?;

    Ok(EncryptedMessage {
        version: ENCRYPTED_MESSAGE_VERSION,
        x25519_ephemeral_pub: x25519_ephemeral_pub,
        ml_kem_ciphertext: kyber_ct,
        poly1305_nonce: nonce.to_vec(),
        ciphertext,
    })
}

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

    let salt = b"Facet's bilattice v1 lib";
    let direction = b"1to1 message sender->recipient";
    let mut ikm = Zeroizing::new([0u8; 64]);

    let kyber_ss = kem::Kem::new(KEM_ALGORITHM)?.decapsulate(
        &recipient.kp_sec.kyber,
        &encrypted_content.ml_kem_ciphertext,
    )?;
    let x25519_ss = recipient
        .kp_sec
        .x25519
        .diffie_hellman(&encrypted_content.x25519_ephemeral_pub);

    ikm[..32].copy_from_slice(x25519_ss.as_bytes());
    ikm[32..].copy_from_slice(kyber_ss.as_ref());

    let transcript_hash = {
        let mut h = Sha3_256::new();

        h.update(b"facet-bilattice-v1 transcript");
        h.update(b"alg:x25519+ml-kem+hkdf-sha3-256+chacha20poly1305");

        h.update(b"x25519_ephemeral_pub");
        h.update(encrypted_content.x25519_ephemeral_pub.as_bytes());

        h.update(b"recipient_x25519_pub");
        h.update(recipient.kp_pub.x25519.as_bytes());

        h.update(b"recipient_kyber_pub");
        h.update(recipient.kp_pub.kyber.as_ref());

        h.update(b"kyber_ciphertext");
        h.update(encrypted_content.ml_kem_ciphertext.as_ref());

        let out: [u8; 32] = h.finalize().into();
        out
    };

    let hk = Hkdf::<Sha3_256>::new(Some(salt), &ikm[..]);

    let mut info = Vec::new();
    info.extend_from_slice(b"chacha20poly1305 key");
    info.extend_from_slice(b"\0");
    info.extend_from_slice(&transcript_hash);
    info.extend_from_slice(b"\0");
    info.extend_from_slice(direction);

    let mut out = Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut out[..])
        .map_err(|err| anyhow::anyhow!("HKDF-SHA3 expand failed: {}", err))?;
    let key = &out[..32];
    let nonce_bytes = &out[32..44];
    if encrypted_content.poly1305_nonce.as_slice() != nonce_bytes {
        anyhow::bail!("encrypted message nonce does not match derived nonce");
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid ChaCha20Poly1305 key length"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    Ok(cipher
        .decrypt(nonce, encrypted_content.ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("ChaCha20Poly1305 decryption failed"))?)
}
