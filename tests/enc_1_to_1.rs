use anyhow::Result;
use bilattice::{decrypt_1_to_1, encrypt_1_to_1, generate_keypair};

#[test]
fn encrypt_decrypt_1_to_1_roundtrip() -> Result<()> {
    let (enc_bob, _sig_bob) = generate_keypair()?;
    let plaintext = b"elenasigmalera";

    let encrypted = encrypt_1_to_1(plaintext.to_vec(), &enc_bob.kp_pub)?;
    let decrypted = decrypt_1_to_1(encrypted, &enc_bob)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn decrypt_fails_with_wrong_recipient_keypair() -> Result<()> {
    let (enc_bob, _sig_bob) = generate_keypair()?;
    let (enc_mallory, _sig_mallory) = generate_keypair()?;

    let encrypted = encrypt_1_to_1(b"secret for bob".to_vec(), &enc_bob.kp_pub)?;

    assert!(decrypt_1_to_1(encrypted, &enc_mallory).is_err());
    Ok(())
}

#[test]
fn decrypt_fails_when_ciphertext_is_tampered() -> Result<()> {
    let (enc_bob, _sig_bob) = generate_keypair()?;

    let mut encrypted = encrypt_1_to_1(b"untampered".to_vec(), &enc_bob.kp_pub)?;
    encrypted.ciphertext[0] ^= 1;

    assert!(decrypt_1_to_1(encrypted, &enc_bob).is_err());
    Ok(())
}

#[test]
fn decrypt_fails_for_unsupported_encrypted_message_version() -> Result<()> {
    let (enc_bob, _sig_bob) = generate_keypair()?;

    let mut encrypted = encrypt_1_to_1(b"versioned".to_vec(), &enc_bob.kp_pub)?;
    encrypted.version = encrypted.version.wrapping_add(1);

    assert!(decrypt_1_to_1(encrypted, &enc_bob).is_err());
    Ok(())
}
