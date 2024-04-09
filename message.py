from dataclasses import asdict, dataclass, fields
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
        start_dict = asdict(self)
        for field in fields(self):
            if field.type is bytes:
                start_dict[field.name] = b64(start_dict[field.name])
        return start_dict

    @classmethod
    def deserialize(cls, data: dict):
        for field in fields(cls):
            if field.type is bytes:
                data[field.name] = u64(data[field.name])
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
    c1: bytes
    salt: bytes


@dataclass
class Auth3Message(DataclassMessage, Message):
    type_str = "auth3"

    ka_c1: bytes
    c2: bytes


@dataclass
class Auth4Message(DataclassMessage, Message):
    type_str = "auth4"

    ka_c2: bytes

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

    data: bytes

    @classmethod
    def encrypt(cls, k: bytes, msg: Message):
        return cls(ae(k, Message.pack(msg)))

    def decrypt(self, k: bytes) -> Message:
        return Message.unpack(ad(k, self.data))


@dataclass
class PeerAuth1Message(DataclassMessage, Message):
    type_str = "pauth1"

    n_c: int
    a: str
    b: str
    k_a1: bytes


@dataclass
class PeerAuth2Message(DataclassMessage, Message):
    type_str = "pauth2"

    a: str
    b: str
    k_a1: bytes
    k_b1: bytes


@dataclass
class PeerAuth3Message(DataclassMessage, Message):
    type_str = "pauth3"

    n_c: int
    k_a2: bytes
    k_b2: bytes


@dataclass
class PeerAuth4Message(DataclassMessage, Message):
    type_str = "pauth4"

    k_a2: bytes


@dataclass
class PeerAuth5Message(DataclassMessage, Message):
    type_str = "pauth5"

    k_abmsg: bytes


@dataclass
class AuthReqMessage(DataclassMessage, Message):
    type_str = "authr"

    n_1: int
    n_2: int
    a: str
    b: str


@dataclass
class AuthTicketMessage(DataclassMessage, Message):
    type_str = "autht"

    n_1: int
    k_ab: bytes
