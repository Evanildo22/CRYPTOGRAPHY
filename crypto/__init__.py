"""
crypto — cryptographic primitives for secure-file-share.

Import order matches the pipeline:
  kdf → aes → rsa_keys / ecdh → pfs → signatures → fingerprint
"""
