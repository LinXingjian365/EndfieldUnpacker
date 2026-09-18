"""Try various decompression/decoding methods on binary JSON files."""
import struct, os, gzip, zlib, base64

base = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json"

samples = [
    "GameplayConfigMissionAreaTable.json",
    "GameplayConfigWorldEntityRegistry.json",
    "AnimationConfig/anim_cfg_abilityEntity_0008.json",
    "BuffData/buff_abilityentity_interact_bomb_passive.json",
]

for fn in samples:
    fp = os.path.join(base, fn)
    with open(fp, "rb") as f:
        data = f.read()
    
    print(f"\n=== {fn} ({len(data)} B, first byte=0x{data[0]:02X}) ===")
    
    # Try gzip
    try:
        dec = gzip.decompress(data)
        print(f"  GZIP: OK ({len(dec)} bytes) -> {dec[:100]}")
        continue
    except:
        pass
    
    # Try zlib
    try:
        dec = zlib.decompress(data)
        print(f"  ZLIB: OK ({len(dec)} bytes) -> {dec[:100]}")
        continue
    except:
        pass
    
    # Try skipping first byte then gzip
    try:
        dec = gzip.decompress(data[1:])
        print(f"  GZIP(skip1): OK ({len(dec)} bytes) -> {dec[:100]}")
        continue
    except:
        pass
    
    # Try skipping first 4 bytes then gzip
    try:
        dec = gzip.decompress(data[4:])
        print(f"  GZIP(skip4): OK ({len(dec)} bytes) -> {dec[:100]}")
        continue
    except:
        pass
    
    # Try base64 decode
    try:
        # Check if first bytes look base64-ish
        text = data.decode("ascii", errors="replace")
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in text.strip()):
            dec = base64.b64decode(text)
            print(f"  BASE64: OK ({len(dec)} bytes) -> {dec[:100]}")
            continue
    except:
        pass
    
    # Try XOR with 0xFF
    xored = bytes(b ^ 0xFF for b in data)
    try:
        if xored[0] in (0x7B, 0x5B):  # { or [
            # Try to decode as text
            text = xored.decode("utf-8")
            print(f"  XOR(0xFF): OK -> {text[:100]}")
            continue
    except:
        pass
    
    # Try XOR with first byte
    key = data[0]
    xored2 = bytes(b ^ key for b in data)
    try:
        if xored2[0] in (0x7B, 0x5B) and xored2[1] in (0x0D, 0x0A, 0x20, 0x22):
            text = xored2.decode("utf-8", errors="replace")
            if text.startswith("{") or text.startswith("["):
                print(f"  XOR(first_byte=0x{key:02X}): OK -> {text[:100]}")
                continue
    except:
        pass
    
    print(f"  No known compression/encoding detected")
