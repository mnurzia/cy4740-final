from argparse import ArgumentParser
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PASS = {"A": 22, "B": 44}
PORT = 25154


def hkdf(n: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"salt", info=b"info"
    ).derive(n.to_bytes(2048))


def ae(k: bytes, p: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, p, None)


def ad(k: bytes, nc: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce, ciphertext = nc[:12], nc[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def u64(b64: str) -> bytes:
    return base64.b64decode(b64)


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
    TYPE_LENGTH_FMT = "8sI"
    TYPE_LENGTH_FMT_SIZE = struct.calcsize(TYPE_LENGTH_FMT)

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

    @classmethod
    def unpack_msg(cls, b: bytes) -> Self:
        msg_type, _ = struct.unpack(
            cls.TYPE_LENGTH_FMT,
            b[: cls.TYPE_LENGTH_FMT_SIZE],
        )
        msg_json = json.loads(b[cls.TYPE_LENGTH_FMT_SIZE :])
        return Message.MESSAGE_CLASSES[
            msg_type.rstrip(b"\0").decode("utf-8")
        ].deserialize(msg_json)

    @classmethod
    def pack_msg(cls, message: Self) -> bytes:
        ser_msg = json.dumps(message.serialize()).encode()
        return (
            struct.pack(cls.TYPE_LENGTH_FMT, message.type_str.encode(), len(ser_msg))
            + ser_msg
        )


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


class ClientsRequestMessage(Message):
    type_str = "clireq"


@dataclass
class ClientsResponseMessage(DataclassMessage, Message):
    type_str = "clires"

    clients: dict[str, str]


@dataclass
class EncryptedMessage(DataclassMessage, Message):
    type_str = "encr"

    data: str

    @classmethod
    def encrypt(cls, k: bytes, msg: Message) -> Self:
        return cls(b64(ae(k, Message.pack_msg(msg))))

    def decrypt(self, k: bytes) -> Message:
        return Message.unpack_msg(ad(k, u64(self.data)))


@dataclass
class PeerAuth1Message(DataclassMessage, Message):
    type_str = "pauth1"

    n_c: int
    a: str
    b: str
    k_a1: str


@dataclass
class PeerAuth2Message(DataclassMessage, Message):
    type_str = "pauth2"

    a: str
    b: str
    k_a1: str
    k_b1: str


@dataclass
class PeerAuth3Message(DataclassMessage, Message):
    type_str = "pauth3"

    n_c: str
    k_a2: str
    k_b2: str


@dataclass
class PeerAuth4Message(DataclassMessage, Message):
    type_str = "pauth4"

    k_a2: str


@dataclass
class PeerAuth5Message(DataclassMessage, Message):
    type_str = "pauth5"

    k_abmsg: str


@dataclass
class AuthReqMessage(DataclassMessage, Message):
    type_str = "authr"

    n_1: str
    n_2: str
    a: str
    b: str


@dataclass
class AuthTicketMessage(DataclassMessage, Message):
    type_str = "autht"

    n_1: str
    k_ab: str


class Node:

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def send_msg(self, writer: asyncio.StreamWriter, message: Message):
        writer.write(Message.pack_msg(message))

    async def receive_msg(self, reader: asyncio.StreamReader) -> Message:
        msg_length: int
        metadata: bytes = await reader.readexactly(Message.TYPE_LENGTH_FMT_SIZE)
        _, msg_length = struct.unpack(Message.TYPE_LENGTH_FMT, metadata)
        msg_bytes = await reader.readexactly(msg_length)
        return Message.unpack_msg(metadata + msg_bytes)

    def send_msg_encrypted(
        self, writer: asyncio.StreamWriter, message: Message, key: bytes
    ):
        self.send_msg(writer, EncryptedMessage.encrypt(key, message))

    async def receive_msg_encrypted(
        self, reader: asyncio.StreamReader, key: bytes
    ) -> Message:
        msg: EncryptedMessage = await self.receive_msg(reader)
        assert isinstance(msg, EncryptedMessage)
        return msg.decrypt(key)


class Server(Node):

    def __init__(self, host: Host):
        super().__init__("server")
        self.server = asyncio.start_server(self._client, str(host.address), host.port)
        self.clients = {}
        self.keys = {}

    async def start(self) -> asyncio.Server:
        return await self.server

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        identity: Optional[str] = None
        try:
            auth1: Auth1Message = await self.receive_msg(reader)
            assert isinstance(auth1, Auth1Message)
            b = int.from_bytes(os.urandom(2048 // 8))
            g_bfw = (pow(G, b, P) + pow(G, PASS[auth1.identity], P)) % P
            u = int.from_bytes(os.urandom(2048 // 8))
            c1 = os.urandom(2048 // 8)
            self.send_msg(
                writer,
                Auth2Message(g_bfw, u, b64(c1)),
            )
            k_a = hkdf(
                (pow(auth1.dh, b, P) * pow(pow(G, PASS[auth1.identity], P), b * u, P))
                % P
            )
            auth3: Auth3Message = await self.receive_msg(reader)
            assert isinstance(auth3, Auth3Message)
            assert ad(k_a, u64(auth3.ka_c1)) == c1
            self.send_msg(writer, Auth4Message(b64(ae(k_a, u64(auth3.c2)))))

            self.clients[identity := auth1.identity] = writer.get_extra_info("peername")
            self.keys[identity] = k_a
            self.logger.info(f"Authenticated to client {identity}")

            while (message := await self.receive_msg_encrypted(reader, k_a)) != None:
                match message:
                    case ClientsRequestMessage():
                        self.send_msg_encrypted(
                            writer, ClientsResponseMessage(self.clients), k_a
                        )
                    case PeerAuth2Message(a, b, k_a1, k_b1):
                        a1: AuthReqMessage = Message.unpack_msg(u64(k_a1)).decrypt(
                            self.keys[a]
                        )
                        assert isinstance(a1, AuthReqMessage)
                        assert a1.a == a and a1.b == b
                        b1: AuthReqMessage = Message.unpack_msg(u64(k_b1)).decrypt(
                            self.keys[b]
                        )
                        assert isinstance(b1, AuthReqMessage)
                        assert b1.a == a and b1.b == b
                        assert a1.n_2 == b1.n_2
                        k_ab: bytes = b64(os.urandom(32))
                        self.send_msg_encrypted(
                            writer,
                            PeerAuth3Message(
                                a1.n_2,
                                b64(
                                    Message.pack_msg(
                                        EncryptedMessage.encrypt(
                                            self.keys[a],
                                            AuthTicketMessage(a1.n_1, k_ab),
                                        )
                                    )
                                ),
                                b64(
                                    EncryptedMessage.pack_msg(
                                        EncryptedMessage.encrypt(
                                            self.keys[b],
                                            AuthTicketMessage(b1.n_1, k_ab),
                                        )
                                    )
                                ),
                            ),
                            k_a,
                        )
                    case _:
                        raise Exception("unexpected message: ", repr(message))
        except Exception as e:
            self.logger.exception(e)
        if identity:
            del self.clients[identity]
            del self.keys[identity]


class Client(Node):
    def __init__(self, host: Host, id: str):
        super().__init__("client")
        self.host = host
        self.k_a: bytes = b""
        self.clients = {}
        self.me: str = id

    async def connect_stdin(self) -> asyncio.StreamReader:
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        return reader

    async def start(self):
        self.peer = asyncio.start_server(self._peer, str(self.host.address), 25154)
        return await asyncio.gather((await self.peer).serve_forever(), self._server())

    async def _peer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            pauth1: PeerAuth1Message = await self.receive_msg(reader)
            assert isinstance(pauth1, PeerAuth1Message)
            n_b = int.from_bytes(os.urandom(16))
            self.send_msg_encrypted(
                self.writer,
                PeerAuth2Message(
                    pauth1.a,
                    self.me,
                    pauth1.k_a1,
                    b64(
                        Message.pack_msg(
                            EncryptedMessage.encrypt(
                                self.k_a,
                                AuthReqMessage(n_b, pauth1.n_c, pauth1.a, self.me),
                            )
                        )
                    ),
                ),
                self.k_a,
            )
            pauth3: PeerAuth3Message = await self.receive_msg_encrypted(
                self.reader, self.k_a
            )
            assert pauth3.n_c == pauth1.n_c
            assert isinstance(pauth3, PeerAuth3Message)
            tick_b: AuthTicketMessage = Message.unpack_msg(u64(pauth3.k_b2)).decrypt(
                self.k_a
            )
            assert isinstance(tick_b, AuthTicketMessage)
            assert tick_b.n_1 == n_b
            k_ab = u64(tick_b.k_ab)
            self.send_msg(writer, PeerAuth4Message(pauth3.k_a2))
            pauth5: PeerAuth5Message = await self.receive_msg(reader)
            assert isinstance(pauth5, PeerAuth5Message)
            print(f"message from {pauth1.a}: {ad(k_ab, u64(pauth5.k_abmsg)).decode()}")

        except Exception as e:
            self.logger.exception(e)

    async def _server(self):
        self.reader, self.writer = await asyncio.open_connection(
            str(self.host.address), self.host.port
        )
        a = int.from_bytes(os.urandom(2048 // 8))
        self.send_msg(self.writer, Auth1Message("A", pow(G, a, P)))
        auth2: Auth2Message = await self.receive_msg(self.reader)
        assert isinstance(auth2, Auth2Message)
        g_b = (auth2.dh - pow(G, PASS["A"], P)) % P
        k_a = hkdf(pow(g_b, a + auth2.u * PASS["A"], P))
        c2 = os.urandom(2048 // 8)
        self.send_msg(self.writer, Auth3Message(b64(ae(k_a, u64(auth2.c1))), b64(c2)))
        auth4: Auth4Message = await self.receive_msg(self.reader)
        assert isinstance(auth4, Auth4Message)
        assert ad(k_a, u64(auth4.ka_c2)) == c2
        self.k_a = k_a
        self.logger.info("Authenticated to server")

        stdin = await self.connect_stdin()

        while True:
            cmd = (await stdin.readline()).decode()
            try:
                match cmd.split():
                    case ["list"]:
                        self.send_msg_encrypted(
                            self.writer, ClientsRequestMessage(), self.k_a
                        )
                        resp: ClientsResponseMessage = await self.receive_msg_encrypted(
                            self.reader, self.k_a
                        )
                        assert isinstance(resp, ClientsResponseMessage)
                        self.clients = resp.clients
                        for user, host in self.clients.items():
                            print(user, ":", host)
                    case ["send", peer, *msg]:
                        await self._update_clients()
                        if peer not in self.clients:
                            raise Exception(f"peer not found: {peer}")
                        peer_read, peer_write = await asyncio.open_connection(
                            self.clients[peer][0], PORT
                        )
                        n_a = int.from_bytes(os.urandom(16))
                        n_c = int.from_bytes(os.urandom(16))
                        self.send_msg(
                            peer_write,
                            PeerAuth1Message(
                                n_c,
                                self.me,
                                peer,
                                b64(
                                    Message.pack_msg(
                                        EncryptedMessage.encrypt(
                                            self.k_a,
                                            AuthReqMessage(n_a, n_c, self.me, peer),
                                        )
                                    )
                                ),
                            ),
                        )
                        pauth4: PeerAuth4Message = await self.receive_msg(peer_read)
                        assert isinstance(pauth4, PeerAuth4Message)
                        tick_a: AuthTicketMessage = Message.unpack_msg(
                            u64(pauth4.k_a2)
                        ).decrypt(self.k_a)
                        assert isinstance(tick_a, AuthTicketMessage)
                        assert tick_a.n_1 == n_a
                        k_ab = u64(tick_a.k_ab)
                        self.send_msg(
                            peer_write,
                            PeerAuth5Message(b64(ae(k_ab, " ".join(msg).encode()))),
                        )
                    case _:
                        raise Exception(f"unexpected command: {cmd}")
            except Exception as e:
                self.logger.exception(e)

    async def _update_clients(self):
        self.send_msg_encrypted(self.writer, ClientsRequestMessage(), self.k_a)
        resp: ClientsResponseMessage = await self.receive_msg_encrypted(
            self.reader, self.k_a
        )
        assert isinstance(resp, ClientsResponseMessage)
        self.clients = resp.clients


async def client_main(args):
    client = Client(Host(args.server_ip, args.server_port), args.id)
    await client.start()


async def server_main(args):
    server = Server(Host(args.server_ip, args.server_port))
    await (await server.start()).serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    ap = ArgumentParser()
    ap.add_argument("server_ip", type=IPv4Address)
    ap.add_argument("server_port", type=int)
    sc = ap.add_subparsers(required=True)
    client = sc.add_parser("client")
    client.set_defaults(func=client_main)
    client.add_argument("id", type=str)
    server = sc.add_parser("server")
    server.set_defaults(func=server_main)
    args = ap.parse_args()
    asyncio.run(args.func(args))
