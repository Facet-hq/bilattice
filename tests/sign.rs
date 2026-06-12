use anyhow::Result;
use bilattice::{generate_keypair, sign, verify};

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
