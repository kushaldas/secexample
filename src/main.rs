#![forbid(unsafe_code)]

//! XML Signature Wrapping (XSW) Attack Demonstration
//!
//! This example shows:
//! 1. How a legitimate SAML-like XML document is signed
//! 2. How an attacker can perform an XSW attack to inject malicious content
//! 3. How a naive verifier is fooled by the attack
//! 4. How bergshamra's security features detect and reject XSW attacks

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

fn print_separator() {
    println!("{}", "=".repeat(72));
}

fn main() {
    println!();
    print_separator();
    println!("  XML Signature Wrapping (XSW) Attack Demonstration");
    println!("  Using bergshamra - Pure Rust XML Security Library");
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
    print_separator();
    println!("  SUMMARY");
    print_separator();
    println!();
    println!("  The XSW attack moves the legitimately signed content to an");
    println!("  unexpected location and injects forged content at the original");
    println!("  position. The XML signature remains mathematically valid because");
    println!("  the signed bytes have not changed -- they have just been relocated.");
    println!();
    println!("  Defences provided by bergshamra:");
    println!();
    println!("  1. DUPLICATE ID DETECTION (always on)");
    println!("     Rejects documents where two elements share the same Id.");
    println!("     Forces attackers to strip/change Ids, making attacks harder.");
    println!();
    println!("  2. STRICT VERIFICATION MODE (ctx.strict_verification = true)");
    println!("     Requires that each signed reference resolves to the document");
    println!("     root, an ancestor of Signature, or a sibling of Signature.");
    println!("     This blocks XSW attacks that relocate signed content.");
    println!();
    println!("  3. TRUSTED KEYS ONLY (ctx.trusted_keys_only = true)");
    println!("     Ignores inline keys in KeyInfo and only uses pre-loaded keys.");
    println!("     Prevents attackers from signing with their own key.");
    println!();
    println!("  4. VERIFY RESULT INSPECTION");
    println!("     VerifyResult::Valid carries `references` metadata showing");
    println!("     exactly which nodes the signature covers. Applications should");
    println!("     check that the signature covers the element they consume.");
    println!();
}
