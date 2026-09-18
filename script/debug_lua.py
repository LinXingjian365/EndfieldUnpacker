import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
blc = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\19E3AE45\19E3AE45.blc'

with open(blc, 'rb') as f:
    data = f.read()
nonce = data[:12]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(data[12:])

off = 0
ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
unk1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
name = plain[off:off+name_len].decode('ascii'); off += name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8

print(f'File count: {file_cnt}')
print(f'First chunk header at off {off}')

bt = plain[off]
ver_check = struct.unpack('<I', plain[off+1:off+5])[0]
ascii_cnt = sum(1 for b in plain[off+5:off+37] if 32 <= b < 127)
chunk_len = struct.unpack('<Q', plain[off+37:off+45])[0]
print(f'  block_type={bt} ver={ver_check} ascii_count={ascii_cnt} chunk_len={chunk_len}')

off += 45  # skip chunk header

print(f'\nEntry[0] at off {off}')
print(f'  raw: {" ".join(f"{b:02x}" for b in plain[off:off+30])}')

# Read entry[0] with standard format: type+f1+fieldX+fnLen
type0 = plain[off]; off += 1
f1_0 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fieldX = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fn_len0 = struct.unpack('<H', plain[off:off+2])[0]; off += 2
fn0 = plain[off:off+fn_len0].decode('ascii').rstrip('\x00'); off += fn_len0
off += 56  # skip fixed area

print(f'  type={type0} f1=0x{f1_0:08x} fieldX={fieldX} fnLen={fn_len0} fn="{fn0}"')
print(f'  ends at off {off}')

print(f'\nEntry[1] at off {off}')
print(f'  raw: {" ".join(f"{b:02x}" for b in plain[off:off+50])}')

# Try to find the fn for entry[1] by scanning
print(f'\nScanning for valid fn at +5 to +15 offset from entry[1] start:')
for maybe_fnlen_off in range(3, 20):
    fnl = plain[off+maybe_fnlen_off]
    if fnl <= 0 or fnl > 200:
        continue
    if off + maybe_fnlen_off + 1 + fnl + 56 > len(plain):
        continue
    fn = plain[off+maybe_fnlen_off+1:off+maybe_fnlen_off+1+fnl]
    try:
        fn_str = fn.decode('ascii')
        fn_stripped = fn_str.rstrip('\x00')
        if len(fn_stripped) > 5:
            file_off2 = struct.unpack('<Q', plain[off+maybe_fnlen_off+1+fnl+8+16+16:off+maybe_fnlen_off+1+fnl+8+16+16+8])[0]
            file_len2 = struct.unpack('<Q', plain[off+maybe_fnlen_off+1+fnl+8+16+16+8:off+maybe_fnlen_off+1+fnl+8+16+16+16])[0]
            print(f'  fnLen at +{maybe_fnlen_off}: len={fnl} fn="{fn_stripped}" fileOff={file_off2} fileLen={file_len2}')
    except:
        pass

# Also scan backward from fixed area markers
# Check if ANY byte sequence in the 50-byte window produces a valid fn
# by looking for the hash field (8 bytes that don't look like ASCII)
print(f'\nLooking at entry[1] raw bytes in detail:')
print(f'  off+0: {plain[off]:02x}')
for i in range(1, 10):
    print(f'  off+{i}: 0x{plain[off+i]:02x} ({plain[off+i]})', end="")
    # try to decode as little-endian u32
    if i+3 < 20:
        print(f' u32le={struct.unpack("<I", plain[off+i:off+i+4])[0]}', end="")
    print()

# Show the full 80 bytes for analysis
print(f'\nFull 80-byte hexdump from entry[1]:')
for i in range(0, 80, 16):
    hex_part = ' '.join(f'{b:02x}' for b in plain[off+i:off+min(i+16,80)])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in plain[off+i:off+min(i+16,80)])
    print(f'  {i:4d}: {hex_part:48s}  {ascii_part}')

# Check what's at the position where we'd expect entry[2] etc
# using each possible format
print(f'\n=== Testing ALL 5 entries with each format ===')

# Standard format (type+f1+fieldX/pad+fnLen)
fmt1 = {'name': 'type+f1+fieldX/pad+fnLen (11/8b)', 'first_size': 11, 'next_size': 8}
# Without pad (type+f1+fnLen)
fmt2 = {'name': 'type+f1+fnLen (7b)', 'first_size': 7, 'next_size': 7}
# 1-byte fnLen
fmt3 = {'name': 'type+f1+fnLen(1byte) (6b)', 'first_size': 6, 'next_size': 6}

for fmt in [fmt1, fmt2, fmt3]:
    print(f'\n--- Format: {fmt["name"]} ---')
    o = 134  # start of entry[0]
    for ei in range(5):
        if o >= len(plain):
            break
        sz = fmt['first_size'] if ei == 0 else fmt['next_size']
        type_ = plain[o]
        # read f1
        f1v = struct.unpack('<I', plain[o+1:o+5])[0]
        # fnLen position varies
        if fmt['first_size'] == 11 and ei == 0:
            fnl = struct.unpack('<H', plain[o+9:o+11])[0]
            fn_start = o+11
        elif fmt['next_size'] == 8 and ei > 0:
            fnl = struct.unpack('<H', plain[o+6:o+8])[0]
            fn_start = o+8
        elif fmt['next_size'] == 7:
            fnl = struct.unpack('<H', plain[o+5:o+7])[0]
            fn_start = o+7
        elif fmt['next_size'] == 6:
            fnl = plain[o+5]
            fn_start = o+6

        if fn_start + fnl + 56 > len(plain):
            fn_str = '(truncated)'
            file_off_val = -1
        else:
            fn = plain[fn_start:fn_start+fnl]
            try:
                fn_str = fn.decode('ascii').rstrip('\x00')
            except:
                fn_str = repr(fn)
            file_off_val = struct.unpack('<Q', plain[fn_start+fnl+8+16+16:fn_start+fnl+8+16+16+8])[0]
            file_len_val = struct.unpack('<Q', plain[fn_start+fnl+8+16+16+8:fn_start+fnl+8+16+16+16])[0]

        entry_sz = sz + fnl + 56
        print(f'  [{ei}] off={o} type={type_} f1=0x{f1v:08x} fnLen={fnl} fn="{fn_str}"', end="")
        if fn_start + fnl + 56 <= len(plain):
            print(f' fileOff={file_off_val} fileLen={file_len_val}')
        else:
            print()

        o = fn_start + fnl + 56
