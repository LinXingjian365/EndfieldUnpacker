"""
Brute-force search for the ChaCha20 key in GameAssembly.dll binary.
Uses first byte of BLC decrypted data must be 0x7b ('{') as oracle.
"""

import struct, os, sys
from Crypto.Cipher import ChaCha20

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_game_dir

_GAME = get_game_dir()
ga = os.path.join(_GAME, 'GameAssembly.dll')
blc_path = os.path.join(_GAME, 'Endfield_Data', 'StreamingAssets', 'VFS', '0CE8FA57', '0CE8FA57.blc')

# Read BLC to get nonce and first encrypted byte
with open(blc_path, 'rb') as f:
    blc_data = f.read()

nonce = blc_data[:12]
enc_first = blc_data[12]  # First encrypted byte
# We need keystream[0] such that keystream[0] ^ enc_first = 0x7b ('{')
target_ks = enc_first ^ 0x7b
print(f'Target keystream[0] = 0x{target_ks:02x} (enc_first=0x{enc_first:02x})', flush=True)

# Also prepare second byte check for verification
enc_second = blc_data[13]

# Read GameAssembly.dll
print(f'Loading {ga}...', flush=True)
with open(ga, 'rb') as f:
    binary = f.read()

print(f'Searching {len(binary)} bytes for 32-byte keys...', flush=True)

# Search every 32-byte aligned position
found = []
count = 0
# Limit scan to first 50MB to speed up (most data sections are early)
scan_limit = min(len(binary) - 32, 50 * 1024 * 1024)

for offset in range(0, scan_limit, 32):
    count += 1
    if count % 100000 == 0:
        print(f'  Progress: {offset}/{scan_limit} ({100*offset//scan_limit}%)', flush=True)
    
    key = binary[offset:offset+32]
    
    # Quick filter: keys should have no null bytes and reasonable entropy
    if b'\x00' in key:
        continue
    
    # Generate keystream block 0 and check first byte
    try:
        c = ChaCha20.new(key=key, nonce=nonce)
        # Consume block 0 (counter=1)
        c.decrypt(b'\x00' * 64)
        ks_first = c.decrypt(bytes(1))[0]
    except Exception as e:
        continue
    
    if ks_first != target_ks:
        continue
    
    # Verify with second byte
    c2 = ChaCha20.new(key=key, nonce=nonce)
    c2.decrypt(b'\x00' * 64)
    ks_second = c2.decrypt(bytes(2))[1]
    expected_second = enc_second ^ 0x0a  # '\n' typically after '{'
    
    if ks_second == enc_second ^ 0x0a or ks_second == enc_second ^ 0x22:  # '"' is also common after '{'
        found.append((offset, key, ks_first))
        print(f'\n*** CANDIDATE at offset 0x{offset:x} ***', flush=True)
        print(f'  Key: {key.hex().upper()}', flush=True)
        
        # Full decrypt check
        c3 = ChaCha20.new(key=key, nonce=nonce)
        c3.decrypt(b'\x00' * 64)
        dec = c3.decrypt(blc_data[12:12+64])
        print(f'  Decrypted: {dec[:64]}', flush=True)
        if dec[:1] == b'{':
            print(f'  *** VALID KEY! BLC decrypted to JSON ***', flush=True)
            sys.exit(0)

print(f'\nScan complete. Candidates found: {len(found)}', flush=True)
for offset, key, ks in found:
    print(f'  0x{offset:x}: {key.hex().upper()}', flush=True)
