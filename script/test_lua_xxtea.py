import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import xxtea_key
"""
Test XXTEA decryption on Lua files.
LuaProcessor flow: base64 decode → XXTEA decrypt → normalize newlines.
"""
import base64, os, struct

XXTEA_KEY = xxtea_key()
DELTA = 0x9E3779B9

def xxtea_decrypt(data, key):
    if not data:
        return b""
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    padded_len = ((len(data) + 3) // 4) * 4
    padded = bytearray(padded_len)
    padded[:len(data)] = data
    v = list(struct.unpack(f"<{padded_len // 4}I", bytes(padded)))
    n = len(v)
    if n < 2:
        return bytes(data)
    k = list(struct.unpack("<4I", key))
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
    original = v[n - 1]
    max_len = n * 4
    min_len = max(0, max_len - 7)
    if min_len <= original <= max_len:
        result = result[:original]
    return result

def normalize_newlines(data):
    """Match LuaProcessor NormalizeNewlines."""
    out = bytearray()
    seen_non_ws = False
    last_was_empty = False
    for b in data:
        if b == 0x0d:
            continue
        if b == 0x0a:
            if seen_non_ws:
                out.append(0x0a)
                last_was_empty = False
            elif not last_was_empty:
                out.append(0x0a)
                last_was_empty = True
            seen_non_ws = False
            continue
        if b != 0x20 and b != 0x09:
            seen_non_ws = True
        out.append(b)
        last_was_empty = False
    return bytes(out)

# Test on Init.lua
path = "D:/Upan/Hypergryph/Hypergryph Launcher/games/unity/zmdobj/LuaScripts/Init.lua"
with open(path, "rb") as f:
    raw = f.read()

# Step 1: Trim whitespace (like LuaProcessor)
text = raw.decode("utf-8").strip()

# Step 2: Base64 decode
encrypted = base64.b64decode(text)
print(f"Encrypted data: {len(encrypted)} bytes")
print(f"First 32 hex: {encrypted[:32].hex()}")

# Step 3: XXTEA decrypt
decrypted = xxtea_decrypt(encrypted, XXTEA_KEY)
print(f"Decrypted: {len(decrypted)} bytes")

# Step 4: Normalize newlines
normalized = normalize_newlines(decrypted)

try:
    lua_text = normalized.decode("utf-8")
    print(f"\nLua text ({len(lua_text)} chars):")
    print(lua_text[:500])
    if lua_text.startswith("--") or lua_text.startswith("--[[") or "function" in lua_text[:200] or "require" in lua_text[:200]:
        print("\nLooks like valid Lua!")
except UnicodeDecodeError:
    print(f"\nNot UTF-8. First 64 hex: {normalized[:64].hex()}")
