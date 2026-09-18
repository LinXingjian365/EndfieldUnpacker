import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

key = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\0CE8FA57'

# Check CHK file structure
chk_files = [f for f in os.listdir(vfs) if f.endswith('.chk')]
print(f'CHK files in 0CE8FA57: {len(chk_files)}', flush=True)
for cf in sorted(chk_files)[:3]:
    fp = os.path.join(vfs, cf)
    sz = os.path.getsize(fp)
    with open(fp, 'rb') as fh:
        raw = fh.read()
    print(f'  {cf}: {sz} bytes', flush=True)
    # Check if it looks like encrypted data
    print(f'    First 32 bytes: {raw[:32].hex()}', flush=True)
    # Try potential nonce(s) - CHK data might be encrypted with its own nonce
    # Nonce could be: file offset bytes, first 12 bytes, etc.
    # Try decrypting with various nonces
    for nstart in [0, 8, 12, 16]:
        if nstart + 12 <= len(raw):
            nonce = raw[nstart:nstart+12]
            c = ChaCha20.new(key=key, nonce=nonce)
            plain = c.decrypt(raw[12:]) if nstart == 0 else c.decrypt(raw[nstart:])
            # Check if plaintext looks valid (starts with common header)
            if len(plain) > 4:
                first_bytes = plain[:4].hex()
                readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in plain[:32])
                print(f'    Decrypt with nonce@{nstart}: {first_bytes} "{readable}"', flush=True)
    print()
