import struct, os

"""
Try to extract ChaCha20 key from GameAssembly.dll using Il2CPP v29 metadata.
Approach: Find the CodeRegistration structure and traverse method pointers to find GetCommonChachaKeyBs.
"""

ga = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\GameAssembly.dll'
md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'

with open(ga, 'rb') as f:
    binary = f.read()

with open(md, 'rb') as f:
    metadata = f.read()

# Parse PE to get image base and section info
e_lfanew = struct.unpack('<I', binary[0x3C:0x40])[0]
opt_start = e_lfanew + 24
magic = struct.unpack('<H', binary[opt_start:opt_start+2])[0]

# For PE32+, image base is at offset 0x18 from optional header start
image_base = struct.unpack('<Q', binary[opt_start+0x18:opt_start+0x20])[0]
print(f'Image base: 0x{image_base:x}', flush=True)

# Section headers
sec_size = magic == 0x20b and 112 or 96
sec_start = e_lfanew + 24 + sec_size + 4
num_sections = struct.unpack('<H', binary[e_lfanew+4+2:e_lfanew+4+4])[0]

sections = []
for i in range(num_sections):
    ss = sec_start + i * 40
    sname = binary[ss:ss+8].rstrip(b'\x00')
    svsize = struct.unpack('<I', binary[ss+8:ss+12])[0]
    srva = struct.unpack('<I', binary[ss+12:ss+16])[0]
    srsize = struct.unpack('<I', binary[ss+16:ss+20])[0]
    srptr = struct.unpack('<I', binary[ss+20:ss+24])[0]
    sections.append((sname, srva, svsize, srptr, srsize))
    print(f'  {sname}: VA=0x{srva+image_base:x} RVA=0x{srva:x} VSize=0x{svsize:x} RPtr=0x{srptr:x}', flush=True)

def va2off(va):
    for sname, srva, svsize, srptr, srsize in sections:
        rva = va - image_base
        if srva <= rva < srva + max(svsize, srsize):
            return rva - srva + srptr
    return None

def rva2off(rva):
    for sname, srva, svsize, srptr, srsize in sections:
        if srva <= rva < srva + max(svsize, srsize):
            return rva - srva + srptr
    return None

# CodeRegistration was found at VA 0x18b9217c0 by Il2CppDumper
code_reg_va = 0x18b9217c0
code_reg_off = va2off(code_reg_va)
print(f'\nCodeRegistration at VA=0x{code_reg_va:x}, file offset=0x{code_reg_off:x}', flush=True)

if code_reg_off:
    # For Il2CPP v29, CodeRegistration structure contains:
    # - codeRegistration (int): pointer to an array of method pointers
    # - metadataRegistration (int): pointer to metadata registration (0 for v29.1)
    # Actually the structure varies by version. Let me dump the raw data.
    print(f'Raw data at CodeRegistration:', flush=True)
    for i in range(0, 256, 16):
        chunk = binary[code_reg_off+i:code_reg_off+i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f'  0x{code_reg_off+i:08x}: {hex_str}', flush=True)
    
    # In modern Il2CPP (v24+), the CodeRegistration has:
    # at +0: int32_t n methods
    # at +4: method pointers array (one per generic method)
    # etc.
    
    # Let me try to parse the structure
    print('\nParsing CodeRegistration:', flush=True)
    
    # The first field is typically the number of methods or code registration entries
    # Let's try reading different-sized values
    vals = struct.unpack('<20Q', binary[code_reg_off:code_reg_off+160])
    val_names = ['codeRegistration', 'metadataRegistration', 'codeGenModules', 'numCodeGenModules',
                 'codeGenModuleProxies', 'numCodeGenModuleProxies', 'genericMethodPointers', 
                 'numGenericMethodPointers', 'genericMethodPointersX', 'numGenericMethodPointersX',
                 'externalMethodPointerProxies', 'numExternalMethodPointerProxies', 
                 'methodPointerProxies', 'numMethodPointerProxies',
                 'reversePInvokeWrapperPointers', 'numReversePInvokeWrapperPointers',
                 'windowsRuntimeMetadataRegistrations', 'numWindowsRuntimeMetadataRegistrations',
                 'genericMethodPointerProxies', 'numGenericMethodPointerProxies']
    
    for name, val in zip(val_names, vals):
        if val != 0:
            print(f'  {name}: 0x{val:x}', flush=True)
else:
    print('Cannot resolve CodeRegistration offset', flush=True)

# Also try to find GetCommonChachaKeyBs method in metadata
# The method name is at offset 0xc832fd in the metadata string pool
# In Il2CPP, methods reference their names by string index.
# Let me try to find the method definition associated with this string.

# In Il2CPP v24+ metadata, the string pool is organized as:
# - stringLiteralsOffset (offset to the start of string literal data)
# - stringLiteralsSize (size of the string literal section)
# - stringLiteralsCount (number of strings)

# Let me find the string literal section offset from the header
# For v29, the header fields at specific offsets:
# From Il2CppInspector source code:
# v24+ header has:
#   0x00: magic
#   0x04: version
#   0x08: stringLiteralOffset  (offset within metadata to string data)
#   0x0c: stringLiteralSize
#   0x10: stringLiteralCount

string_off = struct.unpack('<I', metadata[0x08:0x0C])[0]
string_sz = struct.unpack('<I', metadata[0x0C:0x10])[0]
string_cnt = struct.unpack('<I', metadata[0x10:0x14])[0]
print(f'\nMetadata header:')
print(f'  stringLiteralOffset: 0x{string_off:x}')
print(f'  stringLiteralSize: {string_sz}')
print(f'  stringLiteralCount: {string_cnt}')

# Actually these values might be wrong (string_off=264 is too small).
# Let me look for the correct string pool location.
# The string pool in v24+ has variable-length encoded length prefixes.
# Let me find "GetCommonChachaKeyBs" and parse backwards to find its string index.

kw = b'GetCommonChachaKeyBs'
idx = metadata.find(kw)
print(f'\nSearching for "{kw.decode()}":')
print(f'  Found at metadata offset 0x{idx:x}')

# In v24+, strings in the string pool are stored as:
# - compressed length (1-5 bytes, similar to LEB128)
# - UTF-8 bytes
# Strings are indexed 0..N-1

# Let me parse the length backwards from the string start
# Try to find the correct length prefix
for back in range(1, 10):
    pos = idx - back
    if pos < 0:
        break
    # Try various decoding schemes
    # Il2CPP uses a variable-length encoding for string lengths
    # where bytes have bit 7 set for continuation
    # The length is decoded from consecutive bytes
    
    val = 0
    valid = False
    for j in range(back):
        b = metadata[pos + j]
        if b & 0x80:  # continuation bit
            # Val += (b & 0x7f) << (j * 7) -- but for short strings, 
            # the encoding might be simpler
            pass
    
    # Alternative: Il2CPP just stores a simple compressed integer
    # where the high bit(s) indicate how many bytes
    if back == 1 and metadata[pos] < 0x80:
        val = metadata[pos]
        valid = True
    elif back == 1:
        # Single byte where the actual length might be masked
        val = metadata[pos] & 0x7F
        valid = True
    elif back == 2 and (metadata[pos] & 0x80):
        val = ((metadata[pos] & 0x7F) << 7) | (metadata[pos+1] & 0x7F)
        valid = True
    
    if valid and val == len(kw):
        print(f'  Length prefix at -{back} bytes: val={val}')
        # Now check if there's a string index before this
        str_data_start = pos
        # The string index should be derivable from the position
        # Strings are stored sequentially. The offset of a string in the 
        # string pool can be used to calculate its index.
        print(f'  String data starts at offset 0x{str_data_start:x}')
        break

# Actually, let me try to find the string index differently.
# In Il2CPP metadata, string indices are used in many places:
# type definitions, method definitions, field definitions, etc.
# Each string has a 0-based index based on its position in the string pool.

# The string pool starts at stringLiteralOffset (which we need to find correctly).
# Let me search for the real string pool start by finding the first string.

# I know "ChaCha" is at 0x1358dd. Let me work backwards from there.
print(f'\nChaCha at 0x1358dd, trying to find string start:')
for back in range(1, 20):
    pos = 0x1358dd - back
    if pos < 0:
        break
    # Try different length encoding schemes
    # In Il2CPP v24+, strings are encoded as:
    # - For strings < 128 bytes: 1 byte length prefix
    # - For strings >= 128 bytes: multi-byte length prefix with continuation bit
    
    # Let's check if pos points to a valid length prefix
    # The string that starts with 'ChaCha' is "ChaCha state has been disposed..."
    # which is much longer than 128 chars, so it needs multi-byte encoding
    
    # In Il2CPP metadata, the length encoding for v24+ is:
    # bytes[0] & 0x7F for bits 0-6
    # bytes[1] & 0x7F for bits 7-13
    # etc. (like LEB128)
    
    # Let me try to find the actual encoded length by reading bytes going forward
    # and decoding the variable-length integer
    candidate_pos = 0x1358dd - back
    # Read forward trying to decode a length
    decoded_len = 0
    shift = 0
    for k in range(5):  # Max 5 bytes for LEB128
        if candidate_pos + k >= len(metadata):
            break
        b = metadata[candidate_pos + k]
        decoded_len |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            # This might be a valid length prefix
            expected_str = metadata[candidate_pos+k+1:candidate_pos+k+1+decoded_len]
            # Check if decoded_len is reasonable (not too large)
            if decoded_len > 0 and decoded_len < 500 and len(expected_str) == decoded_len:
                # Check if this is the right string by looking for expected content
                if expected_str.find(b'ChaCha') >= 0 and expected_str.find(b'disposed') >= 0:
                    print(f'  Length prefix found at -{back} ({candidate_pos}): {decoded_len} bytes')
                    print(f'  First 60 chars: {expected_str[:60]}')
                    # Calculate the string index
                    # The string data starts at string_pool_start
                    # string_index = (string_pool_offset - string_pool_start) / something
                    break
            break
    else:
        continue
    break
