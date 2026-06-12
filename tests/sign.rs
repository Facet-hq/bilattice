use anyhow::Result;
use bilattice::{generate_keypair, sign, verify};
use oqs::sig;

#[test]
fn verify_roundtrip() -> Result<()> {
    let (_enc_alice, sig_alice) = generate_keypair()?;
    let plaintext = b"elenasigmalera";

    let signed = sign(plaintext.to_vec(), &sig_alice.kp_sec)?;
    let verification = verify(&signed, &sig_alice.kp_pub);

    assert!(
        verification.is_ok(),
        "signature verification failed: {verification:?}"
    );

    Ok(())
}

#[test]
fn verify_fails_when_signed_content_is_tampered() -> Result<()> {
    let (_enc_alice, sig_alice) = generate_keypair()?;

    let mut signed = sign(b"original".to_vec(), &sig_alice.kp_sec)?;
    signed.content[0] ^= 1;

    let verification = verify(&signed, &sig_alice.kp_pub);
    assert!(
        verification.is_err(),
        "tampered signed content verified unexpectedly"
    );

    Ok(())
}

#[test]
fn verify_fails_with_wrong_sender_public_key() -> Result<()> {
    let (_enc_alice, sig_alice) = generate_keypair()?;
    let (_enc_mallory, sig_mallory) = generate_keypair()?;

    let signed = sign(b"message from alice".to_vec(), &sig_alice.kp_sec)?;

    let verification = verify(&signed, &sig_mallory.kp_pub);
    assert!(
        verification.is_err(),
        "signature verified against the wrong sender public key"
    );

    Ok(())
}

#[test]
fn signatures_are_not_valid_over_raw_content() -> Result<()> {
    oqs::init();
    let (_enc_alice, sig_alice) = generate_keypair()?;
    let content = b"domain separated";

    let signed = sign(content.to_vec(), &sig_alice.kp_sec)?;

    assert!(
        sig_alice
            .kp_pub
            .ed25519
            .verify_strict(content, &signed.ed25519_sign)
            .is_err(),
        "Ed25519 signature verified over raw content"
    );

    let sig_alg = sig::Sig::new(sig::Algorithm::MlDsa65)?;
    assert!(
        sig_alg
            .verify(content, &signed.dilithium_sign, &sig_alice.kp_pub.dilithium)
            .is_err(),
        "ML-DSA signature verified without a context string"
    );

    Ok(())
}
