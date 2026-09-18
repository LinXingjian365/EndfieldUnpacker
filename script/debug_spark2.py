import struct

fn = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigMissionAreaTable.json"
with open(fn, 'rb') as f:
    data = f.read()

print(f"File: {len(data)} bytes")

# 1-byte offset
print(f"\n-- 1-byte offset (skip first byte):")
typ = data[0]
type_names = ['Bool','Byte','Int','Long','Float','Double','Enum','String','Bean','Array','Map']
tname = type_names[typ] if typ <= 10 else '?'
print(f"  first byte = {typ} ({tname})")
i32_1 = struct.unpack_from('<i', data, 1)[0]
i32_5 = struct.unpack_from('<i', data, 5)[0]
i32_9 = struct.unpack_from('<i', data, 9)[0]
print(f"  i32[1]={i32_1} i32[5]={i32_5} i32[9]={i32_9}")
print(f"  At type_def {i32_1}: {' '.join(f'{b:02X}' for b in data[i32_1:i32_1+32])}")
print(f"  At root_def {i32_5}: {' '.join(f'{b:02X}' for b in data[i32_5:i32_5+64])}")
print(f"  At data {i32_9}: {' '.join(f'{b:02X}' for b in data[i32_9:i32_9+32])}")

# Try to parse from byte 1
print(f"\n-- Parsing from byte 1...")
import sys
sys.path.insert(0, r"D:\Upan\Hypergryph\Hypergryph Launcher\games\opencode\EndfieldUnpacker")
from decode_sparkbuffer import parse_sparkbuffer
try:
    name, parsed = parse_sparkbuffer(data[1:])
    import json
    print(f"  OK! name={name}")
    print(f"  Result: {json.dumps(parsed, indent=2)[:500]}")
except Exception as e:
    print(f"  FAIL: {e}")
