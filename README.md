# secexample -- XML Signature Wrapping (XSW) Attack Demo

A practical demonstration of XML Signature Wrapping attacks and how to
defend against them using [bergshamra](https://crates.io/crates/bergshamra),
a pure-Rust XML Security library.

## What is an XSW attack?

XML Digital Signatures protect the **integrity** of specific elements in an
XML document. The signature covers a set of bytes identified by a URI
reference (e.g. `URI="#_assertion123"`), not the document as a whole.

An XML Signature Wrapping attack exploits this by **relocating** the
legitimately signed element to a different position in the document tree and
inserting forged content at the position the application expects to read.
Because the signed bytes are unchanged -- just moved -- the signature remains
mathematically valid.

This is especially dangerous in SAML, where a Service Provider verifies the
XML signature on a `<Response>` or `<Assertion>` and then extracts the
authenticated user identity from the assertion. If the SP does not confirm
that the signature actually covers the assertion it processes, an attacker
can inject an arbitrary identity.

### Attack performed in this demo

The demo implements **XSW variant 3**:

```
LEGITIMATE DOCUMENT            ATTACKED DOCUMENT
=====================          =====================
<Response>                     <Response>
  <Assertion Id="_a123">         <Assertion>              <-- forged (no Id)
    <Subject>                      <Subject>
      alice@example.com              admin@evil.com
    </Subject>                     </Subject>
    <Signature>                  </Assertion>
      (signs #_a123)             <Extensions>
    </Signature>                   <Assertion Id="_a123"> <-- original (buried)
  </Assertion>                       <Subject>
</Response>                            alice@example.com
                                     </Subject>
                                     <Signature>
                                       (signs #_a123)
                                     </Signature>
                                   </Assertion>
                                 </Extensions>
                               </Response>
```

The signature reference `#_assertion123` still resolves to the original
assertion inside `<Extensions>`, so verification succeeds. A naive
application that processes "the first `<Assertion>` child of `<Response>`"
picks up the forged one instead.

## Defences demonstrated

### 1. Duplicate ID detection (always on)

Bergshamra unconditionally rejects documents containing two elements with
the same `Id` attribute value. This forces the attacker to either strip or
change the `Id` on the forged element, which limits the attack surface. In
this demo the forged assertion has no `Id` at all.

### 2. Trusted keys only (`ctx.trusted_keys_only = true`)

When enabled, bergshamra ignores inline keys embedded in `<KeyInfo>`
(`<KeyValue>`, `<X509Certificate>`, etc.) and only uses keys pre-loaded
into the `KeysManager`. Without this, an attacker who controls the XML can
embed their own key and produce a valid signature.

### 3. Strict verification mode (`ctx.strict_verification = true`)

When enabled, bergshamra enforces that every same-document reference target
is:

- the document root element, or
- an ancestor of `<Signature>`, or
- a sibling of `<Signature>`.

This blocks many XSW variants where signed content is moved to an
unexpected depth in the tree.

### 4. Reference inspection (`VerifyResult::references`)

A successful verification returns `VerifyResult::Valid` which carries a
`references` field listing every `<Reference>` and the `NodeId` it resolved
to. Applications **must** check that the signature covers the element they
intend to consume. The secure verifier in this demo confirms that the signed
node is a direct child of the document element -- if it has been wrapped
inside an `<Extensions>` element, the check fails.

## Running

```bash
cargo run
```

Sample output:

```
========================================================================
  XML Signature Wrapping (XSW) Attack Demonstration
  Using bergshamra - Pure Rust XML Security Library
========================================================================

[1] Generating EC P-256 key pair...
    Done.

[2] Creating and signing SAML-like document...
    Subject: alice@example.com
    Assertion Id: _assertion123
    Document signed successfully.

[3] Verifying legitimate signed document...
    Naive verifier:  VALID - signature verified
    Secure verifier: VALID - signature verified, references validated
    Both verifiers accept the legitimate document.

  ATTACK PHASE

[4] Performing XML Signature Wrapping attack...
    Attack document created.

[5] Verifying attacked document...

    NAIVE VERIFIER (no XSW protection):
    Result: VALID - signature verified
    DANGER: Naive verifier accepted the forged document!
    An application would now process admin@evil.com as authenticated.

    SECURE VERIFIER (strict_verification + trusted_keys_only):
    Result: REJECTED - signed content is not a direct child of the document root
    SAFE: Secure verifier correctly rejected the forged document!
```

## Recommended SAML configuration

```rust
use bergshamra_dsig::context::DsigContext;
use bergshamra_keys::manager::KeysManager;

let mut ctx = DsigContext::new(keys_manager);
ctx.trusted_keys_only = true;     // reject inline keys
ctx.strict_verification = true;   // reject unexpected reference positions
```

After verification succeeds, always inspect `VerifyResult::references` to
confirm the signature covers the element your application consumes.

## License

BSD-2-Clause
