import os
import struct

MUL_CONST = 81861667
XOR_CONST = 0x9C5A0B29

def derive_key(seed):
    k = ((seed & 0xFF) ^ XOR_CONST) * MUL_CONST & 0xFFFFFFFF
    k = (k ^ ((seed >> 8) & 0xFF)) * MUL_CONST & 0xFFFFFFFF
    k = (k ^ ((seed >> 16) & 0xFF)) * MUL_CONST & 0xFFFFFFFF
    k = (k ^ ((seed >> 24) & 0xFF)) * MUL_CONST & 0xFFFFFFFF
    return k

def decrypt_vfs(data, start, length, seed, data_offset=0):
    key_index = (seed + (data_offset >> 2)) & 0xFFFFFFFF
    pos = start
    remaining = length
    alignment = data_offset & 3
    if alignment != 0:
        key = derive_key(key_index)
        to_align = min(4 - alignment, remaining)
        for i in range(to_align):
            if pos >= start + length:
                break
            byte_pos = alignment + i
            data[pos] ^= (key >> (byte_pos * 8)) & 0xFF
            pos += 1
        remaining -= to_align
        key_index = (key_index + 1) & 0xFFFFFFFF
    block_count = remaining // 4
    for _ in range(block_count):
        key = derive_key(key_index)
        val = struct.unpack_from("<I", data, pos)[0] ^ key
        struct.pack_into("<I", data, pos, val)
        pos += 4
        key_index = (key_index + 1) & 0xFFFFFFFF
    trailing = remaining & 3
    if trailing > 0:
        key = derive_key(key_index)
        for i in range(trailing):
            data[pos] ^= (key >> (i * 8)) & 0xFF
            pos += 1

def decrypt_wem(data, wem_id):
    decrypt_vfs(data, 0, len(data), wem_id, 0)

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

class WemEntry:
    def __init__(self, wem_id, offset, size, language=None, skip_decrypt=False):
        self.wem_id = wem_id
        self.offset = offset
        self.size = size
        self.language = language
        self.skip_decrypt = skip_decrypt

def parse_akpk(data):
    if data[:4] == b":)xD":
        header_size = read_u32(data, 4)
        decrypt_vfs(data, 12, header_size - 4, header_size, 0)
        data[0:4] = b"AKPK"
        struct.pack_into("<I", data, 8, 1)
    if data[:4] != b"AKPK":
        raise ValueError("Not a valid AKPK file")
    pos = 4
    header_size = read_u32(data, pos); pos += 4
    flag = read_u32(data, pos); pos += 4
    langs_sector_size = read_u32(data, pos); pos += 4
    banks_sector_size = read_u32(data, pos); pos += 4
    sounds_sector_size = read_u32(data, pos); pos += 4
    externals_sector_size = 0
    if langs_sector_size + banks_sector_size + sounds_sector_size + 0x10 < header_size:
        externals_sector_size = read_u32(data, pos); pos += 4
    languages = {}
    if langs_sector_size > 0:
        parse_languages(data, pos, langs_sector_size, languages)
    pos += langs_sector_size
    entries = []
    if banks_sector_size > 0:
        parse_sector(data, pos, banks_sector_size, False, False, languages, entries)
    pos += banks_sector_size
    if sounds_sector_size > 0:
        parse_sector(data, pos, sounds_sector_size, True, False, languages, entries)
    pos += sounds_sector_size
    if externals_sector_size > 0:
        parse_sector(data, pos, externals_sector_size, True, True, languages, entries)
    return entries, data

def parse_languages(data, start, size, languages):
    pos = start
    count = read_u32(data, pos); pos += 4
    for _ in range(count):
        lang_off = read_u32(data, pos); pos += 4
        lang_id = read_u32(data, pos); pos += 4
        sp = start + lang_off
        end = sp
        while end < len(data) and data[end] != 0:
            end += 1
        name = data[sp:end].decode("utf-8", errors="replace")
        languages[lang_id] = name

def parse_sector(data, start, size, is_sounds, is_externals, languages, entries):
    if size == 0:
        return
    pos = start
    count = read_u32(data, pos); pos += 4
    if count == 0:
        return
    entry_size = (size - 4) // count
    alt_mode = entry_size == 0x18
    for _ in range(count):
        file_id_low = read_u32(data, pos)
        p = pos + 4
        file_id_high = None
        if alt_mode and is_externals:
            file_id_high = read_u32(data, p)
            p += 4
        block_size = read_u32(data, p); p += 4
        if alt_mode and is_externals:
            sz = read_u32(data, p); p += 4
        elif alt_mode:
            sz = read_u64(data, p); p += 8
        else:
            sz = read_u32(data, p); p += 4
        offset = read_u32(data, p); p += 4
        lang_id = read_u32(data, p); p += 4
        if block_size != 0:
            offset *= block_size
        lang = languages.get(lang_id)
        final_id = ((file_id_high << 32) | file_id_low) if file_id_high is not None else file_id_low
        if not is_sounds:
            bnk_data = bytearray(data[offset:offset + sz])
            decrypt_wem(bnk_data, file_id_low & 0xFFFFFFFF)
            data[offset:offset + sz] = bnk_data
            for wid, woff, wsz in parse_bnk(bnk_data):
                entries.append(WemEntry(wid, offset + woff, wsz, lang, skip_decrypt=True))
        else:
            entries.append(WemEntry(final_id, offset, sz, lang))
        pos += entry_size

def parse_bnk(data):
    result = []
    if len(data) < 8 or data[:4] != b"BKHD":
        return result
    bkhd_size = read_u32(data, 4)
    pos = 8 + bkhd_size
    if pos + 8 > len(data) or data[pos:pos+4] != b"DIDX":
        return result
    didx_size = read_u32(data, pos + 4)
    didx_start = pos + 8
    data_start = didx_start + didx_size
    if data_start + 8 > len(data) or data[data_start:data_start+4] != b"DATA":
        return result
    data_off = data_start + 8
    n = didx_size // 12
    for i in range(n):
        p = didx_start + i * 12
        wid = read_u32(data, p)
        woff = read_u32(data, p + 4)
        wsz = read_u32(data, p + 8)
        result.append((wid, data_off + woff, wsz))
    return result

def extract_wem(pkg_data, entry):
    start = entry.offset
    wem_data = bytearray(pkg_data[start:start + entry.size])
    if not entry.skip_decrypt and len(wem_data) >= 4 and wem_data[:4] not in (b"RIFF", b"RIFX"):
        decrypt_wem(wem_data, entry.wem_id)
    return bytes(wem_data)

def main():
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(_script_dir, "DecryptOutput", "Audio", "PCK", "Windows")
    out_dir = os.path.join(_script_dir, "DecryptOutput", "Audio_wem")
    total_wems = 0
    for root, dirs, files in os.walk(base_dir):
        for fname in files:
            if not fname.endswith(".pck"):
                continue
            src = os.path.join(root, fname)
            print(f"Processing {fname}...")
            with open(src, "rb") as f:
                data = bytearray(f.read())
            try:
                entries, pkg_data = parse_akpk(data)
            except Exception as e:
                print(f"  FAIL: {e}")
                continue
            for entry in entries:
                try:
                    wem_bytes = extract_wem(pkg_data, entry)
                except Exception as e:
                    print(f"  FAIL WEM {entry.wem_id}: {e}")
                    continue
                lang_dir = entry.language or "NoLang"
                dst_dir = os.path.join(out_dir, lang_dir)
                os.makedirs(dst_dir, exist_ok=True)
                dst = os.path.join(dst_dir, f"{entry.wem_id}.wem")
                with open(dst, "wb") as f:
                    f.write(wem_bytes)
                total_wems += 1
            print(f"  Extracted {len(entries)} WEM files")
    print(f"\nTotal WEM files extracted: {total_wems} to {out_dir}")

if __name__ == "__main__":
    main()
