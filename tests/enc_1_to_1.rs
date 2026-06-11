use crate::{encrypt_1_to_1,decrypt_1_to_1,generate_keypair};


fn main() -> Result<()> {
    let (enc_alice, sig_alice) = generate_keypair()?;
    let (enc_bob, sig_bob) = generate_keypair()?;

    assert_eq!(decript_1_to_1(encrypt_1_to_1(b"elenasigmalera",&enc_bob.kp_pub)));
    
    Ok(())
}
