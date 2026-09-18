import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

# Analyze second file entry in InitBundle
with open(f'{vfs}/0CE8FA57/0CE8FA57.blc', 'rb') as f:
    data = f.read()
nonce = data[:12]
enc = data[12:]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

print(f'BLC total size: {len(plain)}', flush=True)

# After block header and chunk header, first file entry starts at 0x55
# File 1: type=2, f1=0, f2=1048, fnLen=56, fn at 0x60-0x97
# hash at 0x98, chunkRef at 0xA0, dataMD5 at 0xB0, offset at 0xC0, len at 0xC8
# File 2 starts at 0xD0

# Let me parse file 2 differently - try different field arrangements
off = 0xD0  # Start of file 2 entry

print(f'\nAnalyzing file 2 entry at offset 0x{off:x}:', flush=True)
for i in range(0, 128, 16):
    chunk = plain[off+i:off+i+16]
    h = ' '.join(f'{b:02x}' for b in chunk)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  0x{off+i:04x}: {h:48s} {a}', flush=True)

print(f'\nOffset values around file 2:', flush=True)

# Trial: file entry has NO hash/chunkRef/dataMD5. After fn, directly offset/len
# layout: type(1) + f1(4) + f2(4) + fnLen(2) + fn(N) + offset(8) + len(8)
ft = plain[off]; off += 1
f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
f2 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
fn = plain[off:off+fn_len].decode('ascii', errors='replace')
off += fn_len

print(f'type={ft} f1={f1} f2={f2} fnLen={fn_len} fn="{fn}"', flush=True)
print(f'After fn: off=0x{off:x}', flush=True)

# Try: off + 8 as offset and off + 16 as len
if off + 16 <= len(plain):
    off1 = struct.unpack('<Q', plain[off:off+8])[0]
    ln1 = struct.unpack('<Q', plain[off+8:off+16])[0]
    print(f'Trial A (direct): offset={off1} len={ln1}', flush=True)
    
    off2 = struct.unpack('<I', plain[off:off+4])[0]
    ln2 = struct.unpack('<I', plain[off+4:off+8])[0]
    print(f'Trial B (u32): offset={off2} len={ln2}', flush=True)
    
    off3 = struct.unpack('<I', plain[off+8:off+12])[0]
    ln3 = struct.unpack('<I', plain[off+12:off+16])[0]
    print(f'Trial C (skip8): off={off3} len={ln3}', flush=True)
    
    off4 = struct.unpack('<Q', plain[off+16:off+24])[0] if off+24 <= len(plain) else -1
    ln4 = struct.unpack('<Q', plain[off+24:off+32])[0] if off+32 <= len(plain) else -1
    print(f'Trial D (skip16): off={off4} len={ln4}', flush=True)
    
    # What's at the position where file 1 had offset/len (after dataMD5)?
    # file 1: off at 0xC0 (after dataMD5 at 0xB0-0xBF)
    # Offsets relative: file 1 has hash(8)+chunkRef(16)+dataMD5(16) before offset
    # For file 2, same relative position:
    off_hdr = off  # After fn
    trial_off = off_hdr + 40  # Skip 40 bytes of hash+chunkRef+dataMD5
    if trial_off + 16 <= len(plain):
        off5 = struct.unpack('<Q', plain[trial_off:trial_off+8])[0]
        ln5 = struct.unpack('<Q', plain[trial_off+8:trial_off+16])[0]
        print(f'Trial E (skip40): off={off5} len={ln5} at 0x{trial_off:x}', flush=True)
    
    # Trial: after fn, there's just len (no offset) - sequential from previous file
    # Previous file: off=0, len=2461
    prev_end = 2461
    for skip in [0, 8, 16, 24, 32, 40]:
        if off + skip + 8 <= len(plain):
            val = struct.unpack('<Q', plain[off+skip:off+skip+8])[0]
            print(f'Trial skip={skip}: value={val} (as u64: 0x{val:x})', flush=True)
            if off + skip + 16 <= len(plain):
                val2 = struct.unpack('<Q', plain[off+skip+8:off+skip+16])[0]
                print(f'  + 8 more: {val2} (0x{val2:x})', flush=True)
