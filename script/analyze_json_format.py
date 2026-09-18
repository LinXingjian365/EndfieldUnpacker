"""Analyze the binary JSON format used by JsonData block files."""
import struct, os, re

def analyze(fp, name=""):
    with open(fp, "rb") as f:
        data = f.read()
    print(f"\n=== {name or os.path.basename(fp)} ({len(data)} bytes) ===")
    print(f"First byte: 0x{data[0]:02X}")
    
    # Try to identify structure: check for patterns
    # Look for null-terminated strings
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127:
                i += 1
            s = data[start:i].decode("ascii")
            if len(s) >= 4 and re.match(r'^[A-Za-z0-9_/.-]+$', s):
                strings.append((start, s))
        else:
            i += 1
    
    print(f"Readable strings found: {len(strings)}")
    for off, s in strings[:20]:
        # Show context around each string
        before = data[max(0,off-8):off]
        b_hex = " ".join(f"{b:02X}" for b in before)
        after = data[off+len(s):off+len(s)+8]
        a_hex = " ".join(f"{b:02X}" for b in after)
        print(f"  [{off:6d}] {b_hex} | {s} | {a_hex}")
    if len(strings) > 20:
        print(f"  ... and {len(strings)-20} more")

    # Check if data has float patterns
    print(f"\nTrying to parse as records (first 80 bytes):")
    for i in range(0, min(80, len(data)), 4):
        if i + 4 <= len(data):
            val_i32 = struct.unpack_from("<i", data, i)[0]
            val_f32 = struct.unpack_from("<f", data, i)[0]
            val_u32 = struct.unpack_from("<I", data, i)[0]
            ch = chr(data[i]) if 32 <= data[i] < 127 else "."
            print(f"  [{i:3d}] {data[i]:3d} '{ch}' | i32={val_i32:10d} | u32={val_u32:10d} | f32={val_f32:10.4f}")

# Analyze primary files
base = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json"
analyze(os.path.join(base, "GameplayConfigWorldEntityRegistry.json"), "WorldEntityRegistry")
analyze(os.path.join(base, "AnimationConfig", "anim_cfg_abilityEntity_0008.json"), "anim_cfg_0008")
analyze(os.path.join(base, "BuffData", "buff_abilityentity_interact_bomb_passive.json"), "buff_bomb")
