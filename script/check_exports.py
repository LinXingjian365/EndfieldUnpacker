import struct, os

dll = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\EndfieldBase.dll'
with open(dll, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
opt_start = e_lfanew + 24
magic = struct.unpack('<H', data[opt_start:opt_start+2])[0]
dd_start = opt_start + (112 if magic == 0x20b else 96)

# Section headers
sec_size = magic == 0x20b and 112 or 96
sec_start = e_lfanew + 24 + sec_size + 4
num_sections = struct.unpack('<H', data[e_lfanew+4+2:e_lfanew+4+4])[0]

sections = []
for i in range(num_sections):
    ss = sec_start + i * 40
    srva = struct.unpack('<I', data[ss+12:ss+16])[0]
    svsize = struct.unpack('<I', data[ss+8:ss+12])[0]
    srptr = struct.unpack('<I', data[ss+20:ss+24])[0]
    sname = data[ss:ss+8]
    sections.append((srva, svsize, srptr, sname))

def rva2off(rva):
    for srva, svsize, srptr, sname in sections:
        if srva <= rva < srva + svsize:
            return rva - srva + srptr
    return None

# Parse export
export_rva = struct.unpack('<I', data[dd_start:dd_start+4])[0]
export_sz = struct.unpack('<I', data[dd_start+4:dd_start+8])[0]
print(f'Export RVA=0x{export_rva:x} size={export_sz}', flush=True)

export_off = rva2off(export_rva)
if not export_off:
    print('Cannot resolve export dir', flush=True)
    exit()

export_flags = struct.unpack('<I', data[export_off:export_off+4])[0]
time_stamp = struct.unpack('<I', data[export_off+4:export_off+8])[0]
major_ver = struct.unpack('<H', data[export_off+8:export_off+10])[0]
minor_ver = struct.unpack('<H', data[export_off+10:export_off+12])[0]
name_rva = struct.unpack('<I', data[export_off+12:export_off+16])[0]
ordinal_base = struct.unpack('<I', data[export_off+16:export_off+20])[0]
num_funcs = struct.unpack('<I', data[export_off+20:export_off+24])[0]
num_names = struct.unpack('<I', data[export_off+24:export_off+28])[0]
func_rva_ptr = struct.unpack('<I', data[export_off+28:export_off+32])[0]
name_rva_ptr = struct.unpack('<I', data[export_off+32:export_off+36])[0]
ord_rva = struct.unpack('<I', data[export_off+36:export_off+40])[0]

print(f'Functions: {num_funcs}, Named: {num_names}, OrdBase: {ordinal_base}', flush=True)

name_ptr_off = rva2off(name_rva_ptr)
ord_off = rva2off(ord_rva)
func_addr_off = rva2off(func_rva_ptr)

if name_ptr_off and ord_off:
    for i in range(min(num_names, 30)):
        name_rva_val = struct.unpack('<I', data[name_ptr_off+i*4:name_ptr_off+i*4+4])[0]
        ord_val = struct.unpack('<H', data[ord_off+i*2:ord_off+i*2+2])[0]
        name_off = rva2off(name_rva_val)
        if name_off:
            name = data[name_off:data.index(b'\x00', name_off)].decode('ascii', errors='replace')
            print(f'  [{i}] ord={ord_val+ordinal_base} name={name}', flush=True)
else:
    print(f'name_ptr_off={name_ptr_off} ord_off={ord_off} func_addr_off={func_addr_off}', flush=True)
