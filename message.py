from dataclasses import asdict, dataclass
import json
import struct
from typing import Type

from util import *


class Message:
    MESSAGE_CLASSES: dict[str] = {}
    TYPE_LENGTH_FMT = "8sI"
    TYPE_LENGTH_FMT_SIZE = struct.calcsize(TYPE_LENGTH_FMT)

    type_str: str

    @classmethod
    def __init_subclass__(subcls, **kwargs):
        super().__init_subclass__(**kwargs)
        Message.MESSAGE_CLASSES[subcls.type_str] = subcls

    def serialize(self) -> dict:
        return {}

    @classmethod
    def deserialize(cls, data: dict):
        return cls()

    @classmethod
    def unpack(cls, b: bytes):
        msg_type, _ = struct.unpack(
            cls.TYPE_LENGTH_FMT,
            b[: cls.TYPE_LENGTH_FMT_SIZE],
        )
        msg_json = json.loads(b[cls.TYPE_LENGTH_FMT_SIZE :])
        return Message.MESSAGE_CLASSES[
            msg_type.rstrip(b"\0").decode("utf-8")
        ].deserialize(msg_json)

    @classmethod
    def pack(cls, message) -> bytes:
        ser_msg = json.dumps(message.serialize()).encode()
        return (
            struct.pack(cls.TYPE_LENGTH_FMT, message.type_str.encode(), len(ser_msg))
            + ser_msg
        )


class DataclassMessage:
    @classmethod
    def __init_subclass__(subcls, **kwargs):
        super().__init_subclass__(**kwargs)

    def serialize(self) -> dict:
        return asdict(self)

    @classmethod
    def deserialize(cls, data: dict):
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

@dataclass
class PeerPortMessage(DataclassMessage, Message):
    type_str = "peerport"

    peer_port: int


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
    def encrypt(cls, k: bytes, msg: Message):
        return cls(b64(ae(k, Message.pack(msg))))

    def decrypt(self, k: bytes) -> Message:
        return Message.unpack(ad(k, u64(self.data)))


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