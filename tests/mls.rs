#![cfg(feature = "mls")]

use anyhow::Result;
use bilattice::{generate_keypair, mls};

#[test]
fn mls_xwing_signed_content_roundtrip() -> Result<()> {
    let alice_provider = mls::new_provider()?;
    let bob_provider = mls::new_provider()?;

    let (_alice_enc, alice_sig) = generate_keypair()?;
    let (_bob_enc, bob_sig) = generate_keypair()?;

    let alice_credential = mls::credential(b"alice-device".to_vec(), &alice_sig.kp_pub);
    let bob_credential = mls::credential(b"bob-device".to_vec(), &bob_sig.kp_pub);
    let bob_key_package = mls::key_package(&bob_provider, &bob_sig.kp_sec, bob_credential)?;

    let mut alice_group = mls::create_group(
        &alice_provider,
        &alice_sig.kp_sec,
        b"facet-test-group",
        alice_credential,
    )?;

    let add_messages = mls::add_member(
        &mut alice_group,
        &alice_provider,
        &alice_sig.kp_sec,
        bob_key_package.key_package(),
    )?;
    assert!(!add_messages.commit.is_empty());
    assert!(!add_messages.welcome.is_empty());

    let mut bob_group = mls::join_group_from_welcome(&bob_provider, &add_messages.welcome)?;

    let plaintext = b"hello from MLS plus bilattice".to_vec();
    let outbound = mls::create_signed_application_message(
        &mut alice_group,
        &alice_provider,
        &alice_sig.kp_sec,
        &alice_sig.kp_sec,
        plaintext.clone(),
    )?;
    let serialized_outbound = mls::serialize_message(&outbound)?;

    let signed = mls::process_signed_application_message(
        &mut bob_group,
        &bob_provider,
        &serialized_outbound,
        &alice_sig.kp_pub,
    )?;

    assert_eq!(signed.content, plaintext);
    assert!(mls::xwing_codepoint_is_expected());

    Ok(())
}
