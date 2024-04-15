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
    dh_mask: int


@dataclass
class Auth2Message(DataclassMessage, Message):
    type_str = "auth2"

    dh_masked_pw: int
    nonce: int
    challenge_1: bytes
    salt: bytes


@dataclass
class Auth3Message(DataclassMessage, Message):
    type_str = "auth3"

    resp_1: bytes
    challenge_2: bytes


@dataclass
class Auth4Message(DataclassMessage, Message):
    type_str = "auth4"

    resp_2: bytes


@dataclass
class PeerPortMessage(DataclassMessage, Message):
    type_str = "peerport"

    peer_port: int


class LogoutMessage(Message):
    type_str = "logout"


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

    n_common: int
    sender: str
    receiver: str
    auth_sender: bytes


@dataclass
class PeerAuth2Message(DataclassMessage, Message):
    type_str = "pauth2"

    sender: str
    receiver: str
    auth_sender: bytes
    auth_receiver: bytes


@dataclass
class PeerAuth3Message(DataclassMessage, Message):
    type_str = "pauth3"

    n_common: int
    sender_session: bytes
    receiver_session: bytes


@dataclass
class PeerAuth4Message(DataclassMessage, Message):
    type_str = "pauth4"

    sender_session: bytes


@dataclass
class PeerAuth5Message(DataclassMessage, Message):
    type_str = "pauth5"

    cipher: bytes


@dataclass
class AuthReqMessage(DataclassMessage, Message):
    type_str = "authr"

    n_client: int
    n_common: int
    sender: str
    reciever: str


@dataclass
class AuthTicketMessage(DataclassMessage, Message):
    type_str = "autht"

    n_client: int
    session_key: bytes
