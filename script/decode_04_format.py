"""
Decode 04-type binary JSON files (WorldEntityRegistry format).
Records with: hash(4) + marker(4) + str_len(1) + padding(3) + string(N) + marker(4) + 3_floats(12) + separator(4)
"""
import struct, os, json, re

def decode_04(data):
    """Decode WorldEntityRegistry format (first byte = 0x04)."""
    records = []
    i = 4  # Skip first 4 bytes (unknown header)
    
    while i < len(data) - 20:
        # Look for pattern: XX 00 00 00 04 YY 00 00 00 <string>
        # where XX is a hash, 04 is a marker, YY = string length
        if i + 12 > len(data):
            break
        if data[i+4:i+7] == b'\x00\x00\x04':
            str_len = data[i+7]
            if 1 <= str_len <= 200 and data[i+8:i+11] == b'\x00\x00\x00':
                str_start = i + 11
                str_end = str_start + str_len
                if str_end + 16 > len(data):
                    break
                
                try:
                    s = data[str_start:str_end].decode("ascii", errors="replace")
                except:
                    i += 1
                    continue
                
                # Hash before the marker (4 bytes)
                hash_val = struct.unpack_from("<I", data, i)[0]
                
                # After string: marker + floats
                floats = []
                pos = str_end
                if data[pos:pos+4] == b'\x10\x00\x00\x00':
                    pos += 4
                    for _ in range(3):
                        if pos + 4 <= len(data):
                            floats.append(round(struct.unpack_from("<f", data, pos)[0], 6))
                            pos += 4
                
                # Next record starts after separator
                records.append({
                    "hash": f"0x{hash_val:08X}",
                    "id": s,
                    "position": floats if floats else None,
                })
                i = pos
                continue
        i += 1
    
    return records

def decode_generic(data):
    """Generic decoder for unknown binary formats.
    Extracts all strings and data as a flat list."""
    result = []
    i = 0
    while i < len(data):
        # Look for readable strings with length prefix
        if i + 8 <= len(data) and data[i+4:i+7] == b'\x00\x00\x00':
            str_len = data[i+4]
            if 2 <= str_len <= 200:
                str_start = i + 8
                if str_start + str_len <= len(data):
                    try:
                        s = data[str_start:str_start+str_len].decode("ascii")
                        if all(32 <= ord(c) < 127 for c in s):
                            result.append({"offset": i, "string": s})
                            i = str_start + str_len
                            continue
                    except:
                        pass
        i += 1
    return result

# Test on WorldEntityRegistry
fp = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigWorldEntityRegistry.json"
with open(fp, "rb") as f:
    data = f.read()

print(f"Testing 04 decoder on WorldEntityRegistry ({len(data)} bytes)...")
records = decode_04(data)
print(f"Decoded {len(records)} records")
print(f"First 3: {json.dumps(records[:3], indent=2)}")
print(f"Last 3: {json.dumps(records[-3:], indent=2)}")

# Now test on a 01-type file
print(f"\nTesting generic decoder on MissionAreaTable...")
fp2 = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigMissionAreaTable.json"
with open(fp2, "rb") as f:
    data2 = f.read()
print(f"File: {len(data2)} bytes")
strings = decode_generic(data2)
print(f"Extracted {len(strings)} strings")
for s in strings[:5]:
    print(f"  [{s['offset']:5d}] '{s['string']}'")
