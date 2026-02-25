# secexample -- XML Security Attack Demos

A practical demonstration of three classes of XML signature attacks and how
to defend against them using [bergshamra](https://crates.io/crates/bergshamra),
a pure-Rust XML Security library.

## Attacks demonstrated

| # | Attack | CVE | Defence |
|---|--------|-----|---------|
| 1 | XML Signature Wrapping (XSW) | — | `strict_verification` + reference inspection |
| 2 | Key Injection | — | `trusted_keys_only` |
| 3 | HMAC Truncation | CVE-2009-0217 | `hmac_min_out_len` |

## Running

```bash
cargo run
```

---

## Attack 1: XML Signature Wrapping (XSW)

### What is it?

XML Digital Signatures protect the **integrity** of specific elements
identified by a URI reference (e.g. `URI="#_assertion123"`), not the
document as a whole.

An XSW attack **relocates** the legitimately signed element to a different
position in the document tree and inserts forged content at the position the
application expects to read. Because the signed bytes are unchanged -- just
moved -- the signature remains mathematically valid.

This is especially dangerous in SAML, where a Service Provider verifies the
XML signature on a `<Response>` or `<Assertion>` and then extracts the
authenticated user identity from the assertion.

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

### Defences

1. **Duplicate ID detection** (always on) -- rejects documents with two
   elements sharing the same `Id`, forcing attackers to strip or change Ids.

2. **Strict verification** (`ctx.strict_verification = true`) -- requires
   every reference target to be the document root, an ancestor of
   `<Signature>`, or a sibling of `<Signature>`.

3. **Reference inspection** (`VerifyResult::references`) -- applications
   check that the signature covers the element they intend to consume.

---

## Attack 2: Key Injection

### What is it?

XML Signatures can embed the signer's public key inside `<KeyInfo>` as a
`<KeyValue>`, `<X509Certificate>`, or `<DEREncodedKeyValue>`. A naive
verifier that extracts and trusts this inline key has a circular trust
problem: the attacker generates their own key pair, signs forged content,
and embeds their public key in `<KeyInfo>`. The verifier extracts the
attacker's key, checks the attacker's signature against the attacker's key,
and accepts it.

This completely bypasses the trust model -- the signature is self-asserted
rather than verified against a trusted key.

### Attack performed in this demo

```
LEGITIMATE FLOW                 ATTACK FLOW
=================               =================
IdP signs assertion             Attacker signs assertion
  with IdP private key            with attacker's private key
IdP embeds IdP public key       Attacker embeds attacker's public key
  in <KeyInfo>                    in <KeyInfo>

SP verifies signature           SP verifies signature
  using inline key                using inline key
  (IdP's key -- correct)          (attacker's key -- WRONG TRUST!)
SP accepts alice@example.com    SP accepts admin@evil.com
```

### Defence

**Trusted keys only** (`ctx.trusted_keys_only = true`) -- bergshamra ignores
inline keys from `<KeyInfo>` and only uses keys pre-loaded into the
`KeysManager`. The attacker's embedded key is never extracted, and the
signature fails to verify because the attacker's signature doesn't match
any trusted key.

---

## Attack 3: HMAC Truncation (CVE-2009-0217)

### What is it?

HMAC-based XML signatures support an optional `<HMACOutputLength>` element
that truncates the HMAC output. If an attacker can inject
`<HMACOutputLength>8</HMACOutputLength>` (reducing the HMAC to 1 byte),
the signature becomes brute-forceable in approximately 128 attempts (1 in
256 chance per guess).

This was a widespread vulnerability (CVE-2009-0217) affecting many XML
security implementations including Apache XML Security, .NET, and others.

### Attack performed in this demo

```
LEGITIMATE DOCUMENT              ATTACKED DOCUMENT
===================              ===================
<SignatureMethod                 <SignatureMethod
  Algorithm="hmac-sha256"/>        Algorithm="hmac-sha256">
                                   <HMACOutputLength>8</HMACOutputLength>
                                 </SignatureMethod>

HMAC output: 32 bytes            HMAC output: 1 byte
(256 bits -- infeasible           (8 bits -- brute-force
 to brute-force)                  in ~128 tries)
```

### Defence

**Minimum HMAC output length** (`ctx.hmac_min_out_len = 128`) -- bergshamra
rejects any document where `<HMACOutputLength>` specifies fewer bits than
the configured minimum. The W3C recommendation is at least half the hash
output length; 128 bits is a safe minimum for all HMAC variants.

---

## Recommended configuration

```rust
use bergshamra_dsig::context::DsigContext;
use bergshamra_keys::manager::KeysManager;

let mut ctx = DsigContext::new(keys_manager);
ctx.trusted_keys_only = true;     // reject inline keys (key injection)
ctx.strict_verification = true;   // reject relocated references (XSW)
ctx.hmac_min_out_len = 128;       // reject truncated HMACs (CVE-2009-0217)
```

After verification succeeds, always inspect `VerifyResult::references` to
confirm the signature covers the element your application consumes.

## License

BSD-2-Clause
