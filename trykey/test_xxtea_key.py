import struct, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import xxtea_key

XXTEA_KEY = xxtea_key()

def xxtea_decrypt(data, key):
    if not data:
        return b""
    if len(key) != 16:
        raise ValueError("key must be exactly 16 bytes")

    # Pad to multiple of 4 (zero padding like C# BytesToU32Le)
    padded_len = ((len(data) + 3) // 4) * 4
    padded = bytearray(padded_len)
    padded[:len(data)] = data
    v = list(struct.unpack(f"<{padded_len // 4}I", bytes(padded)))
    n = len(v)
    if n < 2:
        return bytes(data)

    k = list(struct.unpack("<4I", key))
    DELTA = 0x9E3779B9
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & 0xFFFFFFFF
    y = v[0]

    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            left = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))
            right = (s ^ y) + (k[(p & 3) ^ e] ^ z)
            mx = (left ^ right) & 0xFFFFFFFF
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        left = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))
        right = (s ^ y) + (k[0 ^ e] ^ z)
        mx = (left ^ right) & 0xFFFFFFFF
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        s = (s - DELTA) & 0xFFFFFFFF

    result = struct.pack(f"<{n}I", *v)

    # Truncate based on length suffix (same logic as C#)
    original = v[n - 1]
    max_len = n * 4
    min_len = max(0, max_len - 7)
    if min_len <= original <= max_len:
        result = result[:original]

    return result


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(_SCRIPT_DIR, '..', 'DecryptOutput', 'Json', 'SpaceshipCabinData.json')
with open(filepath, "rb") as f:
    enc = f.read()

print(f"Encrypted size: {len(enc)} bytes")
print(f"First 32 hex: {enc[:32].hex()}")

dec = xxtea_decrypt(enc, XXTEA_KEY)
try:
    text = dec.decode("utf-8")
    print(f"\nDecrypted ({len(text)} chars):")
    print(text[:1000])
except UnicodeDecodeError:
    print(f"\nNot UTF-8. First 64 bytes hex: {dec[:64].hex()}")
