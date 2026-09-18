import os

_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.game_dir')

def get_game_dir():
    if os.path.exists(_CACHE):
        with open(_CACHE) as f:
            p = f.read().strip()
            if os.path.isdir(p):
                return p
    p = input("Enter game directory path: ").strip()
    p = os.path.abspath(p)
    with open(_CACHE, 'w') as f:
        f.write(p)
    return p
