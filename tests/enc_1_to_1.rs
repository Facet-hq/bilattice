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
