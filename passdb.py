import json

from util import *

'''
A helper to load in a json of the list of username and passwords
'''
def load_pdb(path: str) -> dict[str, tuple[bytes, bytes]]:
    out = {}
    with open(path, "r") as f:
        obj = json.loads(f.read())
        for id, (salt, pwd) in obj.items():
            out[id] = (u64(salt), u64(pwd))
    return out

'''
A helper to save the json of username and passwords into a json file
'''
def save_pdb(path: str, pdb: dict[str, tuple[bytes, bytes]]):
    out = {id: [b64(salt), b64(pwd)] for id, (salt, pwd) in pdb.items()}
    with open(path, "w") as f:
        f.write(json.dumps(out))
