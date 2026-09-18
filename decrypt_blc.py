from Crypto.Cipher import ChaCha20
import struct, os, sys
from config import get_game_dir
from keys import vfs_key

_GAME = get_game_dir()
key = vfs_key()

blc_path = os.path.join(_GAME, 'Endfield_Data', 'StreamingAssets', 'VFS', '0CE8FA57', '0CE8FA57.blc')
with open(blc_path, 'rb') as f:
    data = f.read()

nonce = data[:12]
enc = data[12:]

c = ChaCha20.new(key=key, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

print(f'Decrypted size: {len(plain)}', flush=True)
print(f'First 256 bytes hex:', flush=True)
for i in range(0, min(256, len(plain)), 16):
    chunk = plain[i:i+16]
    h = ' '.join(f'{b:02x}' for b in chunk)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  {i:04x}: {h:48s} {a}', flush=True)

print(f'\n\nParsing binary structure:', flush=True)
off = 0
version = struct.unpack('<I', plain[off:off+4])[0]
print(f'Version: {version}', flush=True)
off += 4

# Scan for readable strings
while off < min(len(plain), 500):
    if plain[off] < 0x80 and off + plain[off] + 1 < len(plain):
        strlen = plain[off]
        if strlen > 3 and all(32 <= b < 127 for b in plain[off+1:off+1+strlen]):
            s = plain[off+1:off+1+strlen].decode('ascii')
            print(f'  0x{off:04x}: string({strlen}) = "{s}"', flush=True)
            off += 1 + strlen
            continue
    off += 1
