import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20

key = vfs_key()

blc_path = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\0CE8FA57\0CE8FA57.blc'
with open(blc_path, 'rb') as f:
    data = f.read()

print(f'File size: {len(data)}', flush=True)

# Try ALL combinations: nonce lengths of 8 and 12, consume 0 and 64
for nlen in [8, 12]:
    for consume in [0, 64]:
        n = data[:nlen]
        enc_data = data[nlen:]
        c = ChaCha20.new(key=key, nonce=n)
        if consume:
            c.decrypt(b'\x00' * consume)
        dec = c.decrypt(enc_data[:32])
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dec[:32])
        print(f'nonce={nlen} consume={consume}: {dec.hex()[:64]} "{printable}"', flush=True)

# Also try version-separated nonce (bytes 0-3 = version, bytes 4-15 = nonce)
version = data[:4]
nonce_v2 = data[4:16]
enc2 = data[16:]
c = ChaCha20.new(key=key, nonce=nonce_v2)
c.decrypt(b'\x00' * 64)
dec2 = c.decrypt(enc2[:32])
print(f'\nNonce from byte 4 (12 bytes), consume 64: {dec2.hex()[:64]}', flush=True)

# Nonce = bytes 4-11 (8 bytes)
nonce3 = data[4:12]
enc3 = data[12:]
c = ChaCha20.new(key=key, nonce=nonce3)
c.decrypt(b'\x00' * 64)
dec3 = c.decrypt(enc3[:32])
print(f'Nonce 4-11 (8 bytes), consume 64: {dec3.hex()[:64]}', flush=True)

# Try: what if counter is embedded in the nonce?
# The first 4 bytes are `03 00 00 00` which could be version=3
# Or the counter could be 3?
for counter_val in [0, 3]:
    n = data[:12]
    enc_data = data[12:]
    # For pycryptodome, we can't set counter directly
    # But we can simulate different counters by consuming more/less
    # Counter=3 means consume 3 blocks = 192 bytes
    consume = counter_val * 64
    c = ChaCha20.new(key=key, nonce=n)
    if consume:
        c.decrypt(b'\x00' * consume)
    dec = c.decrypt(enc_data[:32])
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dec[:32])
    print(f'counter={counter_val}: {dec.hex()[:64]} "{printable}"', flush=True)
