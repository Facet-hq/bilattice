use anyhow::Result;
use bilattice::{KEY_FINGERPRINT_LEN, generate_keypair};

#[test]
fn encryption_public_key_fingerprint_is_stable() -> Result<()> {
    let (enc_alice, _sig_alice) = generate_keypair()?;

    assert_eq!(
        enc_alice.kp_pub.fingerprint(),
        enc_alice.kp_pub.fingerprint()
    );
    assert_eq!(enc_alice.kp_pub.fingerprint().len(), KEY_FINGERPRINT_LEN);
    assert_eq!(
        enc_alice.kp_pub.fingerprint_hex().len(),
        KEY_FINGERPRINT_LEN * 2
    );

    Ok(())
}

#[test]
fn signing_public_key_fingerprint_is_stable() -> Result<()> {
    let (_enc_alice, sig_alice) = generate_keypair()?;

    assert_eq!(
        sig_alice.kp_pub.fingerprint(),
        sig_alice.kp_pub.fingerprint()
    );
    assert_eq!(sig_alice.kp_pub.fingerprint().len(), KEY_FINGERPRINT_LEN);
    assert_eq!(
        sig_alice.kp_pub.fingerprint_hex().len(),
        KEY_FINGERPRINT_LEN * 2
    );

    Ok(())
}

#[test]
fn public_key_fingerprints_are_domain_separated() -> Result<()> {
    let (enc_alice, sig_alice) = generate_keypair()?;
    let (enc_bob, sig_bob) = generate_keypair()?;

    assert_ne!(enc_alice.kp_pub.fingerprint(), enc_bob.kp_pub.fingerprint());
    assert_ne!(sig_alice.kp_pub.fingerprint(), sig_bob.kp_pub.fingerprint());
    assert_ne!(
        enc_alice.kp_pub.fingerprint_hex(),
        sig_alice.kp_pub.fingerprint_hex()
    );

    Ok(())
}
