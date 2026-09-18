import struct, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from decode_sparkbuffer import parse_sparkbuffer, SparkReader

src_root = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json"

# Test with 1-byte offset (skip first byte)
def try_parse(data, skip=0):
    try:
        name, parsed = parse_sparkbuffer(data[skip:])
        return True, name, parsed
    except Exception as e:
        return False, str(e), None

# Test a few files with different first bytes
files = [
    "GameplayConfigMissionAreaTable.json",  # starts with 01
    "GameplayConfigWorldEntityRegistry.json",  # starts with 04
    "AnimationConfig/anim_cfg_abilityEntity_0008.json",  # starts with 0F FF
    "BuffData/buff_abilityentity_interact_bomb_passive.json",  # starts with 1E
]

for fn in files:
    fp = os.path.join(src_root, fn)
    if not os.path.exists(fp):
        print(f"SKIP {fn} (not found)")
        continue
    with open(fp, 'rb') as f:
        data = f.read()
    print(f"\n--- {fn} ({len(data)} B) ---")
    print(f"First 16 bytes: {' '.join(f'{b:02X}' for b in data[:16])}")
    print(f"First byte: 0x{data[0]:02X}")
    ok, result, parsed = try_parse(data, skip=0)
    print(f"  skip=0: {ok} -> {result[:80] if not ok else 'OK'}")
    if not ok:
        ok2, result2, parsed2 = try_parse(data, skip=1)
        print(f"  skip=1: {ok2} -> {result2[:80] if not ok2 else 'OK'}")
        if ok2:
            import json
            print(f"  Parsed: {json.dumps(parsed2, indent=2)[:200]}")
