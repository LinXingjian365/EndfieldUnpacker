"""
Decode 01-type files more carefully.
These seem to be level/config tables with entity names + position data.
"""
import struct, json, re

def decode_type_01_improved(data):
    """Better decoder for 01-type binary files."""
    if len(data) < 4:
        return {"_size": len(data), "_note": "too small"}
    
    first = data[0]
    second = data[1]
    
    # Try different header structures
    # Common pattern: 01 XX followed by i32 count then records
    
    # Structure A: 01 01 <n_records> <rest>
    if first == 1 and second == 1:
        # Try reading a count at offset 4 (4 bytes)
        if len(data) >= 16:
            candidate_count = struct.unpack_from("<I", data, 12)[0]
            if 1 <= candidate_count <= 10000:
                return _parse_01_records(data, offset=16, count=candidate_count)
    
    # Structure B: 01 04 ... similar
    if first == 1 and second == 4:
        if len(data) >= 16:
            candidate_count = struct.unpack_from("<I", data, 8)[0]
            if 1 <= candidate_count <= 10000:
                return _parse_01_records(data, offset=12, count=candidate_count)

    # Generic: just scan for patterns
    return _scan_01_records(data)

def _parse_01_records(data, offset, count):
    """Parse records following a count field."""
    records = []
    for _ in range(count):
        if offset + 20 > len(data):
            break
        
        # Each record likely: name_len(2) + name(N) + data
        name_len = struct.unpack_from("<H", data, offset)[0]
        if 1 <= name_len <= 200 and offset + 2 + name_len + 16 <= len(data):
            try:
                name = data[offset+2:offset+2+name_len].decode("ascii", errors="replace")
                name = re.sub(r'[^\x20-\x7e]', '', name)
            except:
                offset += 1
                continue
            
            # After name: 3 floats (position?) and possibly more data
            floats_start = offset + 2 + name_len
            floats = []
            pos = floats_start
            while pos + 4 <= len(data) and len(floats) < 6:
                val = struct.unpack_from("<f", data, pos)[0]
                if abs(val) < 1e30:
                    floats.append(round(val, 6))
                else:
                    break
                pos += 4
            
            records.append({"name": name.strip('\x00 ')})
            if floats:
                records[-1]["data"] = floats
            
            # Move to next record (skip rest of record - try 16 bytes after floats)
            offset = pos + 8  # skip some padding
        else:
            offset += 1
    
    return records if records else {"_size": len(data), "_note": "could not parse records"}

def _scan_01_records(data):
    """Scan for string patterns in 01-type data."""
    records = []
    i = max(8, 2)  # skip header
    
    while i < len(data) - 12:
        # Look for length-prefixed strings
        for name_len in range(2, 100):
            if i + 2 + name_len + 12 <= len(data):
                name_len_val = struct.unpack_from("<H", data, i)[0]
                if name_len_val == name_len:
                    try:
                        s = data[i+2:i+2+name_len].decode("ascii")
                        if re.match(r'^[A-Za-z0-9_/.-]+$', s):
                            # Found a valid string - try to extract floats after it
                            floats = []
                            pos = i + 2 + name_len
                            for _ in range(3):
                                if pos + 4 <= len(data):
                                    fval = struct.unpack_from("<f", data, pos)[0]
                                    if abs(fval) < 1e30:
                                        floats.append(round(fval, 6))
                                    pos += 4
                            records.append({"name": s})
                            if floats:
                                records[-1]["data"] = floats
                            i = pos
                            break
                    except:
                        pass
        
        i += 1
    
    return records if records else {"_size": len(data), "_note": "could not parse"}

# Test
fp = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigMissionAreaTable.json"
with open(fp, "rb") as f:
    data = f.read()

print(f"MissionAreaTable ({len(data)} bytes):")
result = decode_type_01_improved(data)
print(json.dumps(result, indent=2)[:500])

# Test more 01-type files
import os
base = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json"
test_files = [
    "GameplayConfigSubGameInstanceDataTable.json",
    "SpaceshipCabinData.json",  # plain JSON but check anyway
]
for fn in test_files:
    fp = os.path.join(base, fn)
    if not os.path.exists(fp):
        continue
    with open(fp, "rb") as f:
        data = f.read()
    if data[0] in (0x7B, 0x5B):
        print(f"\n{fn}: plain JSON (skipped)")
        continue
    print(f"\n{fn} ({len(data)} bytes):")
    result = decode_type_01_improved(data)
    print(json.dumps(result, indent=2)[:300])
