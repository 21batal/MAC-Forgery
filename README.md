# MAC Forgery: Length Extension Attack and HMAC-Based Mitigation

## Overview

This project demonstrates a Message Authentication Code (MAC) forgery attack using a length extension technique against insecure constructions like `MAC = MD5(key || message)`. It also provides a secure implementation using the HMAC construction, which mitigates this class of attack.

Included components:

- Technical background on MACs and cryptographic vulnerabilities
- Implementation of a length extension attack
- Secure alternative using HMAC with SHA-256
- Analysis of the vulnerability and its mitigation

## 1. Background: MAC and Security Considerations

### Message Authentication Codes (MAC)

A MAC is a cryptographic checksum that verifies both the integrity and authenticity of a message. It requires a shared secret key between the sender and receiver.

### Insecure Construction

A commonly misused construction is:

MAC = MD5(key || message)


This is vulnerable to length extension attacks when the underlying hash function follows the Merkle-Damgård structure (e.g., MD5, SHA-1).

### Length Extension Attacks

Attackers can exploit the fact that the internal state of hash functions like MD5 can be inferred from the hash output. Given:

- The original message and its MAC,
- An estimate of the key length,

An attacker can compute a valid MAC for an extended message without knowing the key.

## 2. Length Extension Attack Demo

### Files

- `insecureserver_di.py`: Simulates a server that uses `MD5(key || message)` for authentication.
- `clientattacker_di.py`: Demonstrates the length extension attack using the original message and MAC.

### How to Run

1. Start the insecure server:
   ```bash
   python insecureserver_di.py
Enter a secret key and message.

Note the generated MAC.

Run the attack client:
python clientattacker_di.py


Enter the original message and MAC.

Enter the estimated secret key length.

Provide data to append (e.g., &admin=true).

The client will output a forged message (hex) and forged MAC.

Test the forged message on the insecure server's verification step to observe successful forgery.

Security Impact
This highlights why using H(key || message) with vulnerable hash functions is insecure. Attackers can forge valid MACs for unauthorized data without access to the key.

3. Secure Implementation Using HMAC
File
secure_server.py: A secure server implementation using HMAC with SHA-256.

Features
Uses hmac.new() from Python's hmac module.

Implements constant-time MAC verification using hmac.compare_digest().

Uses SHA-256 instead of MD5.

How to Run
Start the secure server:
python secure_server.py
Enter a secret key and message.

Observe the generated HMAC.

Enter forged message and MAC for testing; the attack should fail.

4. Mitigation Analysis
Why the Original Construction Fails
MD5(key || message) is vulnerable to length extension.

No protection against timing side-channel attacks.

MD5 is weak and deprecated for cryptographic use.

Improvements in the Secure Implementation
Uses HMAC construction:
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
which inherently prevents length extension attacks.

Stronger hash function (SHA-256).

Constant-time comparison protects against timing attacks.

Recommendations
Always use HMAC instead of manual key/message hashing.

Prefer modern hash functions (SHA-256, SHA-3).

Generate cryptographically secure keys and rotate them regularly.

Include nonces or timestamps in protocols to prevent replay attacks.

Enforce defense-in-depth measures such as rate limiting and authentication layers.
5. References
RFC 2104 - HMAC: Keyed-Hashing for Message Authentication

Merkle–Damgård Construction

NIST Guidelines for Hashing Algorithms
