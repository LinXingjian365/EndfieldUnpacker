import os, json

json_root = "D:/Upan/Hypergryph/Hypergryph Launcher/games/unity/zmdobj/Json"

# Sample some files from each category
print("=== Sample files with non-UTF8 first bytes ===")
count = 0
for root, dirs, files in os.walk(json_root):
    for f in sorted(files)[:50000]:
        if not f.endswith('.json'):
            continue
        path = os.path.join(root, f)
        with open(path, 'rb') as fp:
            data = fp.read(32)
        if len(data) == 0:
            continue
        try:
            data.decode('utf-8')
        except:
            # Non-UTF8 - show first 16 hex bytes
            if count < 10:
                rel = os.path.relpath(path, json_root)
                print(f"  {rel}: {data[:16].hex()}")
            count += 1

print(f"\nTotal non-UTF8 files sampled: {count}")

# Now show a valid JSON example
print("\n=== Valid JSON example ===")
for root, dirs, files in os.walk(json_root):
    for f in files:
        if not f.endswith('.json'):
            continue
        path = os.path.join(root, f)
        with open(path, 'rb') as fp:
            data = fp.read(500)
        try:
            text = data.decode('utf-8')
            if text.startswith('{'):
                print(f"  {os.path.relpath(path, json_root)}: {text[:200]}")
                break
        except:
            pass
