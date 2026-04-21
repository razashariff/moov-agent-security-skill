# Verification

This skill file is cryptographically signed by CyberSecAI Ltd.

## SHA-256 Hash
```
9deb0b253b698ba80291b9ab3255188a3392020a06ab9711d81f3166c5dbc4b6
```

## Verify Integrity
```bash
# Check hash
shasum -a 256 SKILL.md
# Expected: 9deb0b253b698ba80291b9ab3255188a3392020a06ab9711d81f3166c5dbc4b6

# Verify ECDSA signature
echo -n "9deb0b253b698ba80291b9ab3255188a3392020a06ab9711d81f3166c5dbc4b6" | openssl dgst -sha256 -verify signing-key-pub.pem -signature SKILL.md.sig
# Expected: Verified OK
```

## Public Key
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpbJRFt8qYOMunGW7kWelp9NdXNrY
ekN/GJbagp2VfkdjBeeY9xad7SLgqup+QL1kWrSbFpllYaJ303UUNnAtzw==
-----END PUBLIC KEY-----
```

## Signature (base64)
```
MEUCIQCiZWy8XGXPnp7HnHFymJ9eEoSDsnoLLITWSte4ILMRogIgebVtDU9AvqzeBkfgplw+VdCiluvLGHF5py5anvUOt+U=
```

Signed by: Raza Sharif, CyberSecAI Ltd
Date: 2026-04-21T09:52:42Z
