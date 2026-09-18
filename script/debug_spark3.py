import struct, os, sys
sys.path.insert(0, r"D:\Upan\Hypergryph\Hypergryph Launcher\games\opencode\EndfieldUnpacker")
from decode_sparkbuffer import parse_sparkbuffer

src_root = r"D:\Upan\Hypergryph\Hypergryph Launcher\games\zmddata"

# TableCfg: should all be valid SparkBuffer
tc_dir = os.path.join(src_root, "TableCfg")
tc_ok = 0; tc_fail = 0
for fn in os.listdir(tc_dir):
    if not fn.endswith(".bytes"):
        continue
    fp = os.path.join(tc_dir, fn)
    with open(fp, "rb") as f:
        data = f.read()
    try:
        name, parsed = parse_sparkbuffer(data)
        tc_ok += 1
    except Exception:
        tc_fail += 1

print(f"TableCfg: {tc_ok} OK, {tc_fail} FAIL ({tc_ok+tc_fail} total .bytes files)")

# Json: should be NOT SparkBuffer (per EndfieldStudio source)
json_dir = os.path.join(src_root, "Json")
json_ok = 0; json_fail = 0; json_plain = 0
for dirpath, dirnames, filenames in os.walk(json_dir):
    for fn in filenames:
        if not fn.endswith(".json"):
            continue
        fp = os.path.join(dirpath, fn)
        with open(fp, "rb") as f:
            data = f.read()
        if len(data) > 0 and data[0] in (0x7B, 0x5B):
            json_plain += 1
            continue
        try:
            name, parsed = parse_sparkbuffer(data)
            json_ok += 1
        except Exception:
            try:
                name, parsed = parse_sparkbuffer(data[1:])
                json_ok += 1
            except Exception:
                json_fail += 1

total = json_ok + json_fail + json_plain
print(f"\nJson: {json_plain} plain JSON, {json_ok} SparkBuffer-OK, {json_fail} NOT-SparkBuffer ({total} total)")
print(f"\n結論：decode_sparkbuffer.py 僅能解碼 TableCfg 的 .bytes 檔案")
print(f"JsonData 區塊的檔案（zmddata/Json/）使用非 SparkBuffer 的遊戲原生格式")
