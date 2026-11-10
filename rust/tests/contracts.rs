use owp_rust::{
    canonical::{canonical_bytes, parse_json},
    digest::sha256_bytes,
    signing::{decode_public_key, verify_payload},
};

#[test]
fn sha256_matches_standard_vector() {
    assert_eq!(
        sha256_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn canonical_bytes_match_python_utf16_and_signing_field_rules() {
    let input = br#"{"signature":"drop","digest":1e-0,"nested":{"digest":"keep"},"\ue000":"BMP","\ud800\udc00":"astral","value":-0}"#;
    let payload = parse_json(input, true).unwrap();
    let expected = "{\"domain\":\"openworkproof/manifest/v0.1\",\"payload\":{\"nested\":{\"digest\":\"keep\"},\"value\":0,\"\u{10000}\":\"astral\",\"\u{e000}\":\"BMP\"}}";
    assert_eq!(
        canonical_bytes("0.1", "manifest", &payload).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn parser_rejects_duplicate_decoded_keys_and_resource_excess() {
    assert!(parse_json(br#"{"a":1,"\u0061":2}"#, true).is_err());
    let wide = format!("{{\"items\":[{}0]}}", "0,".repeat(9_998));
    assert!(parse_json(wide.as_bytes(), true).is_err());
    let deep = format!("{{\"item\":{}0{}}}", "[".repeat(129), "]".repeat(129));
    assert!(parse_json(deep.as_bytes(), true).is_err());
}

#[test]
fn verifies_python_fixture_and_rejects_changed_body() {
    // Signed by the baseline Python implementation with a synthetic test key.
    let fixture = br#"{
        "sequence":1,
        "signature_alg":"Ed25519",
        "signer_key_id":"ed25519:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
        "digest":"471294d00d8c61ebf4ec467b0c9340757eeb81535ab4f2736b34a32f35c5b88c",
        "signature":"yz1o5UWYZ5zFU-oZwNwt9_gAPfGJ5_lSHJoRxIEZidM6dhtFe5wVlt1L05emnn6zIWtGNkhKhSRBxjtbPtpAAQ"
    }"#;
    let key = decode_public_key("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap();
    let mut payload = parse_json(fixture, false).unwrap();
    assert!(verify_payload("0.1", "manifest", &payload, &key));
    payload["sequence"] = 2.into();
    assert!(!verify_payload("0.1", "manifest", &payload, &key));
}
