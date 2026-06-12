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
