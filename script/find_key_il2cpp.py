import struct, os, sys

"""
Parse Il2CPP metadata to find the ChaCha20 decryption key.
Metadata v29.1 structure (reverse-engineered from Il2CppDumper source code).
"""

md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'
with open(md, 'rb') as f:
    data = f.read()

# Verify header
magic = data[0:4]
version = struct.unpack('<I', data[4:8])[0]
assert magic == b'\xAF\x1B\xB1\xFA', 'Bad magic'
print(f'Metadata version: {version} (0x{version:x})', flush=True)

# For v24+ (Il2CPP v29), the metadata header has changed significantly.
# The strings are stored in a compressed format.
# Let me search for type definitions that reference 'ChaCha' or 'VFS'.

# First, let's find all string literals that reference encryption-related terms.
# The strings are indexed: each string has an index, and types/fields/methods
# reference strings by their index.

# Find the string pool. In Il2CPP v24+ metadata, after the header there's:
# - type definitions
# - method definitions
# - field definitions  
# - string literals section with (offset, count) pairs

# The string pool contains null-terminated UTF-8 strings.
# Let me find all strings that look like class/field names.

# Actually, let me use a simpler brute force approach.
# The string literal section stores strings with a length prefix.
# Let's search for "Key" near "ChaCha" or "VFS" in the metadata.

# Known context: "ChaCha" at 0x1358dd is an error message "The ChaCha state has been disposed"
# That's in the string pool portion.

# Let me look at what's around the "VFS" references more carefully.
# "VFS" at 0x83f63 - let's see what this is
print(f'\nContext at 0x83f63 (first VFS reference):', flush=True)
for off in range(0x83f30, 0x83f90):
    if data[off] >= 0x20 and data[off] < 0x7f:
        pass
    else:
        pass
ctx = data[0x83f30:0x83f90]
# Find string boundaries
print(f'  hex: {ctx.hex()}', flush=True)

# Let me just dump all type-like strings (PascalCase, near known references)
# The Il2CPP string pool stores strings with variable length prefix.
# Let me try to understand the string pool structure.

# Approach: find all strings by scanning for non-null bytes, 
# looking for length prefixes around known keywords.

# Actually, let me just search for related keywords in the metadata
# and dump their surrounding context to find class/field names.

keywords = [
    b'VFBlock', b'VFS', b'ChaCha', b'Decrypt', b'Crypto', b'_key',
    b'_aesKey', b'_chachaKey', b'chachaKey', b'chacha_key',
    b'encryptKey', b'EncryptKey', b'decryptKey', b'DecryptKey',
]

results = []
for kw in keywords:
    start = 0
    while True:
        idx = data.find(kw, start)
        if idx == -1:
            break
        # Get context before and after
        ctx_start = max(0, idx - 32)
        ctx_end = min(len(data), idx + 64)
        # Find nearest null bytes to get string boundaries
        real_start = idx
        while real_start > ctx_start and data[real_start-1:real_start+1] not in [b'\x00\x00', b'\x01\x00']:
            if real_start == 0:
                break
            real_start -= 1
        real_end = idx + len(kw)
        while real_end < ctx_end and data[real_end:real_end+1] != b'\x00':
            real_end += 1
        s = data[real_start:real_end].decode('utf-8', errors='backslashreplace')
        results.append((idx, s, kw.decode('ascii')))
        start = idx + 1

print(f'\nFound {len(results)} matches:', flush=True)
for idx, s, kw in results:
    print(f'  0x{idx:06x} ({kw}): {s[:120]}', flush=True)
