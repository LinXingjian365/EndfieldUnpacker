import struct, os, json, sys
sys.path.insert(0, r"D:\Upan\Hypergryph\Hypergryph Launcher\games\opencode\EndfieldUnpacker")
from decode_sparkbuffer import parse_sparkbuffer

samples = [
    ("TableCfg (working)", r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\TableCfg\AbilityEntityAttrTable.bytes"),
    ("Json/MissionAreaTable", r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigMissionAreaTable.json"),
    ("Json/WorldEntityRegistry", r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigWorldEntityRegistry.json"),
    ("Json/SpaceshipCabinData (plain)", r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\SpaceshipCabinData.json"),
]

for label, fp in samples:
    with open(fp, "rb") as f:
        data = f.read()
    ok0, r0 = False, ""
    try:
        name, parsed = parse_sparkbuffer(data)
        ok0 = True
    except Exception as e:
        r0 = str(e)[:60]
    ok1, r1 = False, ""
    try:
        name, parsed = parse_sparkbuffer(data[1:])
        ok1 = True
    except Exception as e:
        r1 = str(e)[:60]
    hdr = " ".join(f"{b:02X}" for b in data[:16])
    print(f"{label}:")
    print(f"  Size={len(data)}  First bytes: {hdr}")
    if ok0:
        print(f"  -> OK as SparkBuffer (skip=0)")
    elif ok1:
        print(f"  -> OK as SparkBuffer (skip=1)")
    else:
        print(f"  -> NOT SparkBuffer  (skip=0: {r0})")
        print(f"     NOT SparkBuffer  (skip=1: {r1})")
    print()
