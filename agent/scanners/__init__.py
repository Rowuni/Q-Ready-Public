"""
scanners/ — Q-Ready agent scanner modules.

Convention — `algorithm` field format
--------------------------------------
All scanners MUST use this format for the `algorithm` field so that
the frontend and scoring engine can normalise values uniformly.

Format: "<FAMILY>-<DETAIL>"  (mixed-case family, hyphen-separated detail)

    RSA-2048          RSA key, 2048-bit modulus
    RSA-4096          RSA key, 4096-bit modulus
    EC-secp256r1      Elliptic curve key on P-256 (OpenSSL curve name)
    EC-secp384r1      Elliptic curve key on P-384
    Ed25519           EdDSA on Curve25519  (no size suffix — size is fixed)
    Ed448             EdDSA on Curve448
    DSA-2048          DSA key, 2048-bit prime
    Unknown-<class>   Unrecognised key type; <class> is the Python type name

Note: family names use the capitalisation shown above.
Do NOT use all-lowercase ("rsa-2048") or all-uppercase ("RSA2048").
"""