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
from typing import NamedTuple, Optional, Type

from message import *
from util import *
from client import *
from server import *
from passdb import *
import signal


async def handle(host):
    await host.finish()


def setup_handling(host):
    asyncio.get_event_loop().add_signal_handler(
        signal.SIGINT, lambda: asyncio.create_task(handle(host))
    )


"""
Starts up a client user
"""


async def client_main(args):
    return Client(Host(args.server_ip, args.server_port), args.id, args.pwd)


"""
Starts up a server
"""


async def server_main(args):
    return Server(Host(args.ip, args.port), args.pdb)


async def node_main(args):
    node: Node = await args.node_func(args)
    setup_handling(node)

    await node.start()


"""
Adds a new username and password to the specified password database
"""


async def pdb_main(args):
    pdb = load_pdb(args.pdb)
    salt = os.urandom(16)
    pdb[args.id] = (salt, scrypt(salt, args.pwd.encode()))
    save_pdb(args.pdb, pdb)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    ap = ArgumentParser()
    ap.add_argument(
        "--pdb",
        type=str,
        default="pdb.json",
        help="the password database that should be referenced",
    )
    sc = ap.add_subparsers(required=True)
    client = sc.add_parser("client", help="starts up a client user")
    client.set_defaults(func=node_main, node_func=client_main)
    client.add_argument("server_ip", type=IPv4Address)
    client.add_argument("server_port", type=int)
    client.add_argument("id", type=str, help="the username of the client logging in")
    client.add_argument("pwd", type=str, help="the password of the client logging in")
    server = sc.add_parser("server", help="starts up a server user")
    server.set_defaults(func=node_main, node_func=server_main)
    server.add_argument("ip", type=IPv4Address)
    server.add_argument("port", type=int)
    pdb = sc.add_parser("add_user", help="adds a new user to the app")
    pdb.set_defaults(func=pdb_main)
    pdb.add_argument("id", type=str)
    pdb.add_argument("pwd", type=str)
    args = ap.parse_args()
    asyncio.run(args.func(args))
