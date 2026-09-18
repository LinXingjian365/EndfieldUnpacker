import os

json_root = "D:/Upan/Hypergryph/Hypergryph Launcher/games/unity/zmdobj/Json"
for fname in ["GameplayConfigNpcProxyTable.json", "GameplayConfigMissionAreaTable.json", "SpaceshipCabinData.json"]:
    path = os.path.join(json_root, fname)
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        print(f"=== {fname} ({len(data)} bytes) ===")
        print(f"  First 64 hex: {data[:64].hex()}")
        # Check if it's ASCII/base64 text
        try:
            text = data.decode("ascii")
            preview = text[:120]
            print(f"  ASCII text: {repr(preview)}")
        except:
            print(f"  Not ASCII text")
        print()
