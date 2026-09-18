"""
Best-effort decoder for Endfield JsonData binary files.
Processes all .json files from DecryptOutput/Json/ to DecryptOutput/Json_decrypted/.
"""
import struct, os, json, sys, re

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_SCRIPT_DIR, "DecryptOutput")

def is_plain_json(data):
    return len(data) > 0 and data[0] in (0x7B, 0x5B)

def try_sparkbuffer(data):
    """Try parsing as SparkBuffer (for TableCfg compatibility)."""
    from decode_sparkbuffer import parse_sparkbuffer
    for skip in (0, 1):
        try:
            name, parsed = parse_sparkbuffer(data[skip:])
            return True, name, parsed
        except Exception:
            pass
    return False, None, None

def decode_type_04(data):
    """WorldEntityRegistry-like: records with hash + string + 3 floats."""
    records = []
    i = 4
    while i < len(data) - 20:
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
                    i += 1; continue
                hash_val = struct.unpack_from("<I", data, i)[0]
                floats = []
                pos = str_end
                while pos + 4 <= len(data) and data[pos:pos+4] == b'\x10\x00\x00\x00':
                    pos += 4
                    for _ in range(3):
                        if pos + 4 <= len(data):
                            val = struct.unpack_from("<f", data, pos)[0]
                            if abs(val) < 1e30:
                                floats.append(round(val, 6))
                            pos += 4
                records.append({"hash": f"0x{hash_val:08X}", "id": s})
                if floats:
                    records[-1]["floats"] = floats
                i = pos
                continue
        i += 1
    return records if records else _dump_meta(data)

def decode_type_01(data):
    """Type 01: level/entity tables with null-terminated strings + float data."""
    # Skip header bytes: usually 01 01 or 01 XX format
    # Look for record count at offset 12
    offset = 2
    records = []
    count = 0
    if len(data) >= 16:
        candidate = struct.unpack_from("<I", data, 12)[0]
        if 1 <= candidate <= 100000:
            count = candidate
            offset = 16
    
    for _ in range(count if count > 0 else 100000):
        if offset >= len(data):
            break
        # Each record: null-terminated string + float data
        null_pos = data.find(b'\x00', offset)
        if null_pos < 0 or null_pos - offset > 500:
            offset += 1
            continue
        try:
            name = data[offset:null_pos].decode("utf-8", errors="replace").strip('\x00 ')
        except:
            offset = null_pos + 1
            continue
        if len(name) < 2:
            offset = null_pos + 1
            continue
        
        # After null term, align to 4 bytes and read floats
        pos = (null_pos + 4) & ~3  # align4
        floats = []
        for _ in range(8):  # up to 8 floats
            if pos + 4 <= len(data):
                val = struct.unpack_from("<f", data, pos)[0]
                if abs(val) < 1e30:
                    floats.append(round(val, 6))
                else:
                    break
                pos += 4
            else:
                break
        
        records.append({"name": name})
        if floats:
            records[-1]["data"] = floats
        offset = pos
        if not count:  # auto-detect: stop after 3 records without count
            if len(records) >= 3:
                break
    
    return records if records else _dump_meta(data)

def decode_type_0f(data):
    """Type 0F: animation/animation-related. Usually small, often empty/null."""
    if len(data) <= 72:
        # Very small files - likely null/empty
        return {"_type": "animation_ref", "_size": len(data), "_note": "compact binary, not decoded"}
    return _dump_meta(data)

def decode_type_1e(data):
    """Type 1E: buff/config data with strings."""
    strings = extract_strings(data)
    return {"_type": "buff_data", "_strings": strings, "_note": "partial decode"} if strings else _dump_meta(data)

def extract_strings(data, min_len=4):
    """Extract all readable ASCII strings."""
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127:
                i += 1
            s = data[start:i].decode("ascii")
            if len(s) >= min_len and re.match(r'^[A-Za-z0-9_./\s-]+$', s):
                strings.append({"offset": start, "value": s})
        else:
            i += 1
    return strings

def _dump_meta(data):
    """Fallback: return metadata about the binary file."""
    return {
        "_size": len(data),
        "_first_bytes": " ".join(f"{b:02X}" for b in data[:32]),
        "_note": "binary format, not decoded",
    }

def decode_file(data):
    """Auto-detect format and decode."""
    if is_plain_json(data):
        return data.decode("utf-8"), True
    
    # Try SparkBuffer
    ok, name, parsed = try_sparkbuffer(data)
    if ok:
        result = json.dumps(parsed, indent=2, ensure_ascii=False)
        return result, True
    
    # Decode by first byte type
    first = data[0]
    if first == 0x04:
        result = decode_type_04(data)
    elif first == 0x01:
        result = decode_type_01(data)
    elif first == 0x0F:
        result = decode_type_0f(data)
    elif first == 0x1E:
        result = decode_type_1e(data)
    else:
        result = _dump_meta(data)
    
    return json.dumps(result, indent=2, ensure_ascii=False), True

if __name__ == "__main__":
    src_root = os.path.join(OUT, "Json")
    dst_root = os.path.join(OUT, "Json_decrypted")
    
    total = ok = fail = plain = 0
    type_counts = {}
    
    print("Decoding JSON files...")
    for dirpath, dirnames, filenames in os.walk(src_root):
        for fn in filenames:
            if not fn.endswith(".json"):
                continue
            src = os.path.join(dirpath, fn)
            with open(src, "rb") as f:
                data = f.read()
            
            total += 1
            if not data:
                continue
                
            if is_plain_json(data):
                plain += 1
                result = data.decode("utf-8")
            else:
                try:
                    result, _ = decode_file(data)
                except Exception as e:
                    result = json.dumps({"_error": str(e), "_size": len(data)}, indent=2)
                    fail += 1
            
            rel = os.path.relpath(src, src_root)
            dst = os.path.join(dst_root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(result)
            ok += 1
            
            if ok % 5000 == 0:
                print(f"  {ok}/{total}...", flush=True)
    
    print(f"\nDone: {ok} written ({plain} plain JSON, {fail} with errors, {total} total)")
