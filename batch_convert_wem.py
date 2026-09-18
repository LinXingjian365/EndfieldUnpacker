import os
import subprocess
import sys
from multiprocessing import Pool
from glob import glob

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WEM_DIR = os.path.join(_SCRIPT_DIR, "DecryptOutput", "Audio_wem")
WAV_DIR = os.path.join(_SCRIPT_DIR, "DecryptOutput", "Audio_wav")
VGSTREAM = os.path.join(_SCRIPT_DIR, "vgmstream-win64", "vgmstream-cli.exe")

def convert_one(wem_path):
    rel = os.path.relpath(wem_path, WEM_DIR)
    wav_path = os.path.join(WAV_DIR, rel).replace(".wem", ".wav")
    os.makedirs(os.path.dirname(wav_path), exist_ok=True)
    try:
        subprocess.run(
            [VGSTREAM, "-o", wav_path, wem_path],
            capture_output=True, timeout=120
        )
        return (wem_path, "ok")
    except Exception as e:
        return (wem_path, str(e))

def main():
    wem_files = glob(os.path.join(WEM_DIR, "**", "*.wem"), recursive=True)
    print(f"Converting {len(wem_files)} WEM files to WAV...")
    nproc = max(1, os.cpu_count() - 1)
    print(f"Using {nproc} processes")
    ok = 0
    fail = 0
    with Pool(nproc) as pool:
        for i, (path, status) in enumerate(pool.imap_unordered(convert_one, wem_files, chunksize=10)):
            if status != "ok":
                print(f"FAIL [{i}] {path}: {status}")
                fail += 1
            else:
                ok += 1
            if (i + 1) % 1000 == 0:
                print(f"  {i+1}/{len(wem_files)} (ok={ok} fail={fail})")
    print(f"\nDone: {ok} OK, {fail} failed of {len(wem_files)}")

if __name__ == "__main__":
    main()
