import base64
import os
import struct

from keys import xxtea_key

XXTEA_KEY = xxtea_key()

def xxtea_decrypt(data, key):
    if len(data) < 4:
        return b""
    v = list(struct.unpack(f"<{len(data)//4}I", data))
    n = len(v)
    if n < 2:
        return bytes(data)
    k = list(struct.unpack("<4I", key))
    q = 6 + 52 // n
    y = v[0]
    DELTA = 0x9E3779B9
    mask = 0xFFFFFFFF
    sum_val = (q * DELTA) & mask
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z)))) & mask
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(0 & 3) ^ e] ^ z)))) & mask
        y = v[0]
        sum_val = (sum_val - DELTA) & mask
    result = struct.pack(f"<{n}I", *v)
    original_len = v[n - 1]
    max_len = n * 4
    min_len = max(0, max_len - 7)
    if min_len <= original_len <= max_len:
        result = result[:original_len]
    return result

def decrypt_lua_file(input_path, output_path):
    with open(input_path, "r", encoding="utf-8") as f:
        b64_data = f.read().strip()
    raw = base64.b64decode(b64_data)
    decrypted = xxtea_decrypt(raw, XXTEA_KEY)
    # Normalize newlines: \r\n -> \n, strip trailing per line
    text = decrypted.decode("utf-8")
    text = text.replace("\r\n", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)

def main():
    lua_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DecryptOutput", "LuaScripts")
    out_dir = lua_dir + "_decrypted"
    count = 0
    for root, dirs, files in os.walk(lua_dir):
        for fname in files:
            if not fname.endswith(".lua"):
                continue
            src = os.path.join(root, fname)
            rel = os.path.relpath(src, lua_dir)
            dst = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                decrypt_lua_file(src, dst)
                count += 1
                if count % 100 == 0:
                    print(f"  {count} done...")
            except Exception as e:
                print(f"FAIL {rel}: {e}")
    print(f"Decrypted {count} Lua files to {out_dir}")

if __name__ == "__main__":
    main()
