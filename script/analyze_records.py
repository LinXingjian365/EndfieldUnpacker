"""Analyze record structure of WorldEntityRegistry."""
import struct

fp = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata\Json\GameplayConfigWorldEntityRegistry.json"
with open(fp, "rb") as f:
    data = f.read()

# Find all string occurrences with context
print("Analyzing record structure...")
print(f"First 4 bytes: {data[0]:02X} {data[1]:02X} {data[2]:02X} {data[3]:02X}")
# First i32 = 4 - could be record count?

# Try to identify record boundaries
# Pattern observed: before each string there's bytes like: 00 00 00 04 XX 00 00 00
# Where XX = string length
# After string: 10 00 00 00 + 3 floats (12 bytes) + 00 00 00 00

records = []
i = 4  # Start after first 4 bytes (which might be count)
record_count = 0

while i < len(data) - 20:
    # Look for pattern: XX 00 00 00 04 XX 00 00 00 <string>
    # Where XX is a reasonable string length (<= 200)
    if data[i:i+4] == b'\x00\x00\x00\x04':  # marker
        str_len = data[i+4]
        if 2 <= str_len <= 200 and data[i+5:i+8] == b'\x00\x00\x00':
            str_start = i + 8
            str_end = str_start + str_len
            if str_end <= len(data):
                try:
                    s = data[str_start:str_end].decode("ascii")
                    if all(32 <= ord(c) < 127 or c in '/_' for c in s):
                        # Found a record! Look for what's before the marker
                        # There should be a hash/ID (4 bytes) before the marker
                        hash_start = i - 4
                        hash_val = struct.unpack_from("<I", data, hash_start)[0] if hash_start >= 0 else 0
                        
                        # Find the record start (search backwards for previous marker or file start)
                        rec_start = i - 8  # Try going back 8 more bytes for more context
                        if rec_start < 0:
                            rec_start = 0
                        
                        # After string, look for 10 00 00 00 marker
                        after_str = str_end
                        float_data = []
                        if after_str + 4 <= len(data) and data[after_str:after_str+4] == b'\x10\x00\x00\x00':
                            after_str += 4
                            # Read 3 consecutive floats (12 bytes)
                            for fi in range(3):
                                if after_str + 4 <= len(data):
                                    fval = struct.unpack_from("<f", data, after_str)[0]
                                    float_data.append(fval)
                                    after_str += 4
                        
                        records.append({
                            "hash": hash_val,
                            "name": s,
                            "floats": float_data,
                            "str_offset": str_start,
                        })
                        record_count += 1
                        i = str_end
                        continue
                except:
                    pass
    i += 1

print(f"\nFound {record_count} records")
print(f"\nFirst 5 records:")
for r in records[:5]:
    print(f"  hash=0x{r['hash']:08X} name='{r['name']}' floats={r['floats']}")

print(f"\nLast 3 records:")
for r in records[-3:]:
    print(f"  hash=0x{r['hash']:08X} name='{r['name']}' floats={r['floats']}")
