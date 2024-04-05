from argparse import ArgumentParser
import asyncio
from dataclasses import asdict, dataclass
from ipaddress import IPv4Address
import json
import logging
import os
import struct
from typing import NamedTuple, Optional, Self, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PASS = {"A": 22}


def hkdf(n: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"salt", info=b"info"
    ).derive(n.to_bytes(2048))


class Host(NamedTuple):
    """
    Helper class to define a host on our chat platform.
    """

    address: IPv4Address
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"

    @classmethod
    def from_str(cls, s: str) -> str:
        address, port = s.split(":")
        return cls(address, int(port))


class Message:
    MESSAGE_CLASSES: dict[str, Type[Self]] = {}

    type_str: str

    @classmethod
    def __init_subclass__(subcls, **kwargs):
        """
        Register subclasses so that we can decode packets using from_json.
        """
        super().__init_subclass__(**kwargs)
        Message.MESSAGE_CLASSES[subcls.type_str] = subcls

    def serialize(self) -> dict:
        return {}

    @classmethod
    def deserialize(cls, data: dict) -> Self:
        return cls()


class DataclassMessage:
    @classmethod
    def __init_subclass__(subcls, **kwargs):
        """
        Register subclasses so that we can decode packets using from_json.
        """
        super().__init_subclass__(**kwargs)

    def serialize(self) -> dict:
        return asdict(self)

    @classmethod
    def deserialize(cls, data: dict) -> Self:
        return cls(**data)


@dataclass
class Auth1Message(DataclassMessage, Message):
    type_str = "auth1"

    identity: str
    dh: int


@dataclass
class Auth2Message(DataclassMessage, Message):
    type_str = "auth2"

    dh: int
    u: int
    c1: int


@dataclass
class Auth3Message(DataclassMessage, Message):
    type_str = "auth3"

    ka_c1: str
    c2: int


@dataclass
class Auth4Message(DataclassMessage, Message):
    type_str = "auth4"

    ka_c2: str


class Node:
    TYPE_LENGTH_FMT = "8sI"
    TYPE_LENGTH_FMT_SIZE = struct.calcsize(TYPE_LENGTH_FMT)

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    async def receive_msg(self, reader: asyncio.StreamReader) -> Optional[Message]:
        try:
            msg_type: str
            msg_length: int
            msg_type, msg_length = struct.unpack(
                self.TYPE_LENGTH_FMT,
                await reader.readexactly(self.TYPE_LENGTH_FMT_SIZE),
            )
            msg_bytes = await reader.readexactly(msg_length)
            msg_json = json.loads(msg_bytes)
            return Message.MESSAGE_CLASSES[
                msg_type.rstrip(b"\0").decode("utf-8")
            ].deserialize(msg_json)
        except Exception as e:
            self.logger.exception(e)
            return None

    def send_msg(self, writer: asyncio.StreamWriter, message: Message):
        ser_msg = json.dumps(message.serialize()).encode()
        out = (
            struct.pack(self.TYPE_LENGTH_FMT, message.type_str.encode(), len(ser_msg))
            + ser_msg
        )
        self.logger.info("writing", str(out))
        writer.write(out)


class Server(Node):

    def __init__(self, host: Host):
        super().__init__("server")
        self.server = asyncio.start_server(self._client, str(host.address), host.port)

    async def start(self) -> asyncio.Server:
        return await self.server

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        print(f"Client acquired {writer.get_extra_info('peername')}")
        auth1: Auth1Message = await self.receive_msg(reader)
        assert isinstance(auth1, Auth1Message)
        b = int.from_bytes(os.urandom(2048 // 8))
        g_bfw = (pow(G, b, P) + pow(G, PASS[auth1.identity], P)) % P
        u = int.from_bytes(os.urandom(2048 // 8))
        c1 = int.from_bytes(os.urandom(2048 // 8))
        self.send_msg(
            writer,
            Auth2Message(g_bfw, u, c1),
        )
        print(pow(G, b, P), u)
        k_a = hkdf(
            (pow(auth1.dh, b, P) * pow(pow(G, PASS[auth1.identity], P), b * u, P)) % P
        )
        print(k_a)


class Client(Node):
    def __init__(self, host: Host):
        super().__init__("client")
        self.host = host

    async def start(self):
        self.reader, self.writer = await asyncio.open_connection(
            str(self.host.address), self.host.port
        )
        a = int.from_bytes(os.urandom(2048 // 8))
        self.send_msg(self.writer, Auth1Message("A", a))
        auth2: Auth2Message = await self.receive_msg(self.reader)
        g_b = (auth2.dh - pow(G, PASS["A"], P)) % P
        print(g_b, auth2.u)
        k_a = hkdf(pow(g_b, (a + auth2.u * PASS["A"]), P))
        print(k_a)


async def client_main(args):
    client = Client(Host(args.server_ip, args.server_port))
    await client.start()


async def server_main(args):
    server = Server(Host(args.server_ip, args.server_port))
    ass = await server.start()
    async with ass:
        await ass.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    ap = ArgumentParser()
    ap.add_argument("server_ip", type=IPv4Address)
    ap.add_argument("server_port", type=int)
    sc = ap.add_subparsers(required=True)
    client = sc.add_parser("client")
    client.set_defaults(func=client_main)
    server = sc.add_parser("server")
    server.set_defaults(func=server_main)
    args = ap.parse_args()
    asyncio.run(args.func(args))
