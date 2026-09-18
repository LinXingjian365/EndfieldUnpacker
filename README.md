# EndfieldUnpacker
## 'Arknights: Endfield' — RE Scripts （明日方舟：终末地 — 逆向工程脚本）
---

Target: Decrypt and extract all game assets.
目标：解密并提取全部游戏资源
Game: Arknights: Endfield (Unity + Il2Cpp, Custom VFS + Endfield AssetBundle)
游戏：明日方舟：终末地（Unity + Il2Cpp，自定义虚拟文件系统 + 终末地专属资源包格式）

## Project Structure （项目目录结构）
---

```
EndfieldUnpacker/              ← Project root（项目根目录）
├── README.md
├── config.py                  ← Game directory prompt + cache (`.game_dir`) （游戏目录选择 + 路径缓存）
├── trykey/                    ← Key brute-force & discovery （密钥暴力枚举与密钥搜寻工具）
│   ├── brute_key.py / brute_key2.py
│   ├── find_key_il2cpp.py / find_v29_key.py
│   ├── search_masterkey.py / test_xxtea_key.py
│   ├── CNKeys.json            ← Known keys from AnimeStudio （AnimeStudio 已知密钥）
│   └── check_*.py / verify_json.py  ← Validation tools （校验工具）
├── decrypt_vfs.py             ← VFS ChaCha20 decryptor （VFS ChaCha20 解密器）
├── decrypt_blc.py             ← BLC index decryption （BLC 索引解密程序）
├── decrypt_lua.py             ← XXTEA Lua (base64 → XXTEA → Lua) （Lua XXTEA解密（Base64解码 → XXTEA解密 → 输出Lua源码））
├── decode_sparkbuffer.py      ← SparkBuffer binary JSON → plain JSON （SparkBuffer 二进制JSON转为明文JSON）
├── batch_convert_wem.py       ← WEM → WAV (vgmstream-cli) （WEM 转 WAV（依托vgmstream-cli））
├── extract_akpk.py            ← AKPK audio extraction （AKPK音频包提取工具）
├── decode_json_other.py       ← JsonData binary → JSON （JsonData 二进制格式解码为JSON）
│
├── vgmstream-win64/            ← WEM→WAV converter (vgmstream-cli) （WEM音频转WAV工具）
│   ├── vgmstream-cli.exe
│   └── *.dll / README.md / USAGE.md
│
├── wwiser/                     ← Wwise PCK parser (wwiser.pyz) （Wwise音频包解析器）
│   └── wwiser.pyz
│
├── AnimeStudio-net10/          ← Unity AssetBundle extractor (CLI+GUI) （Unity资源包提取工具（命令行 + 图形界面））
│   └── AnimeStudio-net10-.../
│       ├── AnimeStudio.CLI.exe   ← <input> <output> --game ArknightsEndfield （使用格式：<输入路径> <输出路径> --game ArknightsEndfield）
│       └── AnimeStudio.GUI.exe   ← GUI version （图形界面版本）
└── script/                    ← Test Code （测试文件）
```

## Game Directory （游戏目录选择）
---

Scripts that need the game files prompt for the game path on first run and cache it in `.game_dir`.
需要读取游戏文件的脚本会在首次运行时提示输入游戏目录，路径会缓存到 `.game_dir`。

```powershell
Enter game directory path: D:\path\to\EndField Game
```

Cache can be cleared by deleting `EndfieldUnpacker/.game_dir`.
删除 `EndfieldUnpacker/.game_dir` 可清除缓存，重新选择目录。

## Usage （使用方式）
---

```powershell
python decrypt_vfs.py dry       # List VFS files （列出VFS内所有文件（试运行，不导出））
python decrypt_vfs.py extract   # Full VFS extract （完整提取VFS资源）
python decrypt_lua.py           # XXTEA Lua decrypt （Lua脚本XXTEA解密）
python batch_convert_wem.py     # WEM → WAV （WEM音频转WAV）
python extract_akpk.py          # AKPK audio （提取AKPK音频包）
python decode_json_other.py     # JsonData binary → JSON （JsonData 二进制格式解码为JSON）
```

## Default Output Directory （默认输出目录）
---

All outputs default to `DecryptOutput/` under the project root:
所有输出默认保存在项目根目录下的 `DecryptOutput/` 中：

```
EndfieldUnpacker/DecryptOutput/
├── Json/              # Raw binary JSON (VFS extract) 原始二进制JSON（VFS提取）
├── Json_decrypted/    # JsonData binary decoded to JSON JsonData二进制解码后的JSON
├── LuaScripts/        # Raw XXTEA-encrypted Lua (VFS extract) 原始XXTEA加密Lua（VFS提取）
├── LuaScripts_decrypted/ # XXTEA-decrypted Lua source XXTEA解密后的Lua源码
├── TableCfg/          # Raw SparkBuffer .bytes (VFS extract) 原始SparkBuffer字节文件（VFS提取）
├── TableCfg_json/     # SparkBuffer decoded to JSON SparkBuffer解码后的JSON
├── Audio/             # PCK audio packages PCK音频包
├── Audio_wem/         # Extracted .wem files 提取的WEM文件
├── Video/             # .usm video files USM视频文件
├── Terrain/           # Terrain data 地形数据
└── Streaming/         # Other streaming assets 其他流式资源
```

## Decryption Pipeline （解密流程）
---

**Layer 1 — VFS (ChaCha20)**: `decrypt_vfs.py` — parses BLC → reads CHK → per-file ChaCha20 decrypt.
第一层 — VFS（ChaCha20 加密）：decrypt_vfs.py — 解析 BLC 索引 → 读取 CHK 数据 → 对每个文件执行 ChaCha20 解密。
**Layer 2 — Per-format**:
第二层 — 各格式专项处理：

| Type | After VFS | 2nd layer | Tool |
|---|---|---|---|
| TableCfg (.bytes) | SparkBuffer binary | SparkBuffer→JSON | `decode_sparkbuffer.py` |
| JsonData (.json) | Custom binary | Binary→JSON | `decode_json_other.py` |
| Lua | Base64 XXTEA | XXTEA decrypt | `decrypt_lua.py` |
| .ab | Endfield format | AnimeStudio | `AnimeStudio.CLI.exe` |
| .pck | Wwise PCK | wwiser.pyz | `wwiser/wwiser.pyz` |
| .usm | CRID USM | CRIWARE tools | external |
| .wem | Encrypted audio | vgmstream waveform | `vgmstream-win64/vgmstream-cli.exe` |
| Terrain | Binary bytes | — | — |

| 文件类型 | VFS解密后状态 | 第二层处理流程 | 对应工具 |
|---|---|---|---|
| TableCfg (.bytes) | SparkBuffer二进制 | SparkBuffer解码为标准JSON | `decode_sparkbuffer.py` |
| JsonData (.json) | 自定义二进制格式 | 二进制解码为JSON | `decode_json_other.py` |
| Lua | Base64编码的XXTEA密文 | XXTEA解密 | `decrypt_lua.py` |
| .ab资源包 | 终末地自定义封装格式 | AnimeStudio解析 | `AnimeStudio.CLI.exe` |
| .pck音频包 | Wwise标准PCK格式 | wwiser.pyz | `wwiser/wwiser.pyz` |
| .usm视频 | CRID标准USM格式 | CRIWARE工具 | 外部工具 |
| .wem音频 | 加密音频流 | vgmstream波形解码 | `vgmstream-win64/vgmstream-cli.exe` |
| 地形数据 | 原始二进制数据 | 无需额外处理 | — |

## Key Material （密钥信息）
---

密钥不以明文形式出现在源码中，统一由 `keys.py` 提供（base64(XOR 0x5A) 编码，运行时自动解码）。

| 用途 | 获取方式 |
|---|---|
| VFS ChaCha20 密钥 | `from keys import vfs_key` |
| Lua XXTEA 密钥 | `from keys import xxtea_key` |
| 单文件随机数 Nonce | LE i32(3) + LE i64(iv_seed) |

> 如需自行定位密钥，参考 `trykey/` 目录下的密钥搜寻/暴力枚举工具。

## Reference （参考项目）
---

- [EIHRTeam/EndfieldStudio](https://github.com/EIHRTeam/EndfieldStudio) - C# port (External VFS Container Decryption) C#实现（外部VFS容器解密）
- [Escartem/AnimeStudio](https://github.com/Escartem/AnimeStudio) — C# port (Unity Asset Parsing, VFS-AES Deobfuscation, Texture2D Decoding) C#实现（Unity资产解析、VFS-AES去混淆、Texture2D解码）
- [fluffield/fluffy-dumper](https://git.nekolab.app/fluffield/fluffy-dumper) — Rust original Rust原版实现
- [british-commies/wwiser](https://github.com/bnm/wwiser) — Wwise PCK parser (wwiser.pyz) Wwise音频包解析器（wwiser.pyz）
- [vgmstream/vgmstream](https://github.com/vgmstream/vgmstream) — WEM→WAV audio converter WEM音频转WAV工具

