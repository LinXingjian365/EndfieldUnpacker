from Crypto.Cipher import ChaCha20
import struct, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_game_dir
from keys import vfs_key

_GAME = get_game_dir()
KEY = vfs_key()
vfs = os.path.join(_GAME, 'Endfield_Data', 'StreamingAssets', 'VFS')
dp = os.path.join(vfs, '0CE8FA57')

with open(dp + '/0CE8FA57.blc', 'rb') as f:
    data = f.read()
nonce = data[:12]
enc = data[12:]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

# Search for u64 value 2461 (file 1 len) and 0 (file 1 offset)
# offset=0 as u64 LE = 00 00 00 00 00 00 00 00
# len=2461 as u64 LE = 9d 09 00 00 00 00 00 00

print("Searching for offset=0, len=2461 pattern...")
target = b'\x00\x00\x00\x00\x00\x00\x00\x00' + b'\x9d\x09\x00\x00\x00\x00\x00\x00'
pos = 0
while True:
    idx = plain.find(target, pos)
    if idx == -1:
        break
    print(f"  Found at offset 0x{idx:x}", flush=True)
    # Show context: 32 bytes before and after
    ctx_start = max(0, idx - 32)
    ctx_end = min(len(plain), idx + len(target) + 32)
    h = ' '.join(f'{plain[ctx_start+j]:02x}' for j in range(ctx_end - ctx_start))
    print(f"  Context: {h}", flush=True)
    pos = idx + 1

# Also search for offset=2461, len=3009
print("\nSearching for offset=2461, len=3009 pattern...")
target2 = b'\x9d\x09\x00\x00\x00\x00\x00\x00' + b'\xc1\x0b\x00\x00\x00\x00\x00\x00'
pos = 0
while True:
    idx = plain.find(target2, pos)
    if idx == -1:
        break
    print(f"  Found at offset 0x{idx:x}", flush=True)
    ctx_start = max(0, idx - 32)
    ctx_end = min(len(plain), idx + len(target2) + 32)
    h = ' '.join(f'{plain[ctx_start+j]:02x}' for j in range(ctx_end - ctx_start))
    print(f"  Context: {h}", flush=True)
    pos = idx + 1

# Dump what's around 0x55-0x150 to understand the structure
print("\n\nFull dump 0x55-0x150:")
for i in range(0x55, 0x150, 16):
    chunk = plain[i:i+16]
    h = ' '.join(f'{b:02x}' for b in chunk)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  0x{i:04x}: {h:48s} {a}", flush=True)
