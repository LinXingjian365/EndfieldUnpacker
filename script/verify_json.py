import os, json

json_root = "D:/Upan/Hypergryph/Hypergryph Launcher/games/unity/zmdobj/Json"

# Check all .json files for validity
total = 0
valid_json = 0
binary = 0
encrypted = 0
errors = []

for root, dirs, files in os.walk(json_root):
    for f in files:
        if f.endswith('.json'):
            path = os.path.join(root, f)
            total += 1
            try:
                with open(path, 'rb') as fp:
                    data = fp.read()
                if len(data) == 0:
                    continue
                # Try JSON parse
                text = data.decode('utf-8')
                json.loads(text)
                valid_json += 1
            except UnicodeDecodeError:
                # Check if still encrypted
                if data[:4] == b'\x03\x01\x54\xdf' or data[:4].hex().startswith('03'):
                    encrypted += 1
                else:
                    binary += 1
            except json.JSONDecodeError:
                if total <= 5:
                    errors.append((f, text[:100]))

print(f"Total .json files: {total}")
print(f"Valid JSON: {valid_json}")
print(f"Binary format: {binary}")
print(f"Still encrypted (ChaCha20): {encrypted}")
if errors:
    print(f"\nFirst {len(errors)} JSON decode errors:")
    for f, t in errors:
        print(f"  {f}: {repr(t)}")
