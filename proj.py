from argparse import ArgumentParser, FileType
import asyncio
import base64
from dataclasses import asdict, dataclass
from ipaddress import IPv4Address
import json
import logging
import os
import struct
import sys
from typing import NamedTuple, Optional, Self, Type

from message import *
from util import *
from client import *
from server import *


async def client_main(args):
    client = Client(Host(args.server_ip, args.server_port), args.id)
    await client.start()


async def server_main(args):
    server = Server(Host(args.ip, args.port))
    await (await server.start()).serve_forever()


def load_pdb(path: str) -> dict[str, tuple[bytes, bytes]]:
    out = {}
    with open(path, "r") as f:
        obj = json.loads(f.read())
        for id, (salt, pwd) in obj:
            out[id] = (u64(salt), u64(pwd))
    return out


def save_pdb(path: str, pdb: dict[str, tuple[bytes, bytes]]):
    out = {id: [b64(salt), b64(pwd)] for id, (salt, pwd) in pdb.items()}
    with open(path, "w") as f:
        f.write(json.dumps(out))


async def pdb_main(args):
    pdb = load_pdb(args.pdb)
    salt = os.urandom(16)
    pdb[args.id] = (salt, scrypt(salt, args.pwd.encode()))
    save_pdb(args.pdb, pdb)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    ap = ArgumentParser()
    ap.add_argument("--pdb", type=str, default="pdb.json")
    sc = ap.add_subparsers(required=True)
    client = sc.add_parser("client")
    client.set_defaults(func=client_main)
    client.add_argument("server_ip", type=IPv4Address)
    client.add_argument("server_port", type=int)
    client.add_argument("id", type=str)
    server = sc.add_parser("server")
    server.set_defaults(func=server_main)
    server.add_argument("ip", type=IPv4Address)
    server.add_argument("port", type=int)
    pdb = sc.add_parser("pass")
    pdb.set_defaults(func=pdb_main)
    pdb.add_argument("id", type=str)
    pdb.add_argument("pwd", type=str)
    args = ap.parse_args()
    asyncio.run(args.func(args))
