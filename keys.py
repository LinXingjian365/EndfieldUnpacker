"""
Shared key material for Arknights: Endfield unpacking scripts.

Keys are stored obfuscated so the plaintext does not appear verbatim in the
source tree. Encoding rule: base64( bytes XOR 0x5A ). Decode at runtime with
`base64.b64decode(...)` then XOR each byte by 0x5A again.
"""
import base64

_XOR = 0x5A

_VFS_ENC = "swFrIJ6icgzHefIxqCuG72TeNf0GyBc9R+DUYq6QCLs="
_XXTEA_ENC = "Pm5rPmI5PmNiPGpqOGhqbg=="


def _dec(encoded: str) -> bytes:
    return bytes(b ^ _XOR for b in base64.b64decode(encoded))


def vfs_key() -> bytes:
    """32-byte ChaCha20 key used for VFS / BLC decryption."""
    return _dec(_VFS_ENC)


def xxtea_key() -> bytes:
    """16-byte XXTEA key used for Lua script decryption."""
    return _dec(_XXTEA_ENC)
