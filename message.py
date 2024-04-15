from dataclasses import asdict, dataclass, fields
import json
import struct
from typing import Type

from util import *

'''
A base class for all messages to be used in the app
'''
class Message:
    MESSAGE_CLASSES: dict[str] = {}
    TYPE_LENGTH_FMT = "8sI"
    TYPE_LENGTH_FMT_SIZE = struct.calcsize(TYPE_LENGTH_FMT)

    type_str: str

    @classmethod
    def __init_subclass__(subcls, **kwargs):
        super().__init_subclass__(**kwargs)
        Message.MESSAGE_CLASSES[subcls.type_str] = subcls

    '''
    Reconstruct the byte array into a json
    '''
    def serialize(self) -> dict:
        return {}

    '''
    Desconstruct the json into a byte array for network transport
    '''
    @classmethod
    def deserialize(cls, data: dict):
        return cls()

    '''
    Construct the byte array into its respective json elements
    '''
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

    '''
    Deconstruct the json into a bytearray for network transmission
    '''
    @classmethod
    def pack(cls, message) -> bytes:
        ser_msg = json.dumps(message.serialize()).encode()
        return (
            struct.pack(cls.TYPE_LENGTH_FMT, message.type_str.encode(), len(ser_msg))
            + ser_msg
        )

'''
A base class for the different messages types in the protocol
'''
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

'''
THe initiation message from the client to the server
'''
@dataclass
class Auth1Message(DataclassMessage, Message):
    type_str = "auth1"

    identity: str
    dh_mask: int

'''
A message from the server to the client with a challenge and the material to construct the session key
'''
@dataclass
class Auth2Message(DataclassMessage, Message):
    type_str = "auth2"

    dh_masked_pw: int
    nonce: int
    challenge_1: bytes
    salt: bytes

'''
A message to the server with a response to the challenge and a challenge of their own for mutual authentication
'''
@dataclass
class Auth3Message(DataclassMessage, Message):
    type_str = "auth3"

    resp_1: bytes
    challenge_2: bytes

'''
A response to the client from the server to their challenge
'''
@dataclass
class Auth4Message(DataclassMessage, Message):
    type_str = "auth4"

    resp_2: bytes

'''
A message that will be encrypted that contains the port that a client is listening on for communciation
'''
@dataclass
class PeerPortMessage(DataclassMessage, Message):
    type_str = "peerport"

    peer_port: int

'''
A logout message to remove a client from the server
'''
class LogoutMessage(Message):
    type_str = "logout"

'''
A message to request the list of clients logged on the server
'''
class ClientsRequestMessage(Message):
    type_str = "clireq"

'''
A response to the client with a list of the clients logged onto the server
'''
@dataclass
class ClientsResponseMessage(DataclassMessage, Message):
    type_str = "clires"

    clients: dict[str, str]

'''
A generally encrrypted message that is to be decrypted
'''
@dataclass
class EncryptedMessage(DataclassMessage, Message):
    type_str = "encr"

    data: bytes

    @classmethod
    def encrypt(cls, k: bytes, msg: Message):
        return cls(ae(k, Message.pack(msg)))

    def decrypt(self, k: bytes) -> Message:
        return Message.unpack(ad(k, self.data))

'''
The initiation of client to client communication
'''
@dataclass
class PeerAuth1Message(DataclassMessage, Message):
    type_str = "pauth1"

    n_common: int
    sender: str
    receiver: str
    auth_sender: bytes

'''
A message from a receiving client (in P2P comm) to the server to confirm the entity of the original sender + the retrieval of a shared key
'''
@dataclass
class PeerAuth2Message(DataclassMessage, Message):
    type_str = "pauth2"

    sender: str
    receiver: str
    auth_sender: bytes
    auth_receiver: bytes

'''
A message from the server to the receiving client (in a P2P comm) confirming the sender's identity and session keys
'''
@dataclass
class PeerAuth3Message(DataclassMessage, Message):
    type_str = "pauth3"

    n_common: int
    sender_session: bytes
    receiver_session: bytes

'''
A message back to the client to client communication initiator with their session key
'''
@dataclass
class PeerAuth4Message(DataclassMessage, Message):
    type_str = "pauth4"

    sender_session: bytes

'''
The actual message from the initiator now that there has been mutual authentication
'''
@dataclass
class PeerAuth5Message(DataclassMessage, Message):
    type_str = "pauth5"

    cipher: bytes

'''
The components in a PeerAuth 1 and 2 message
'''
@dataclass
class AuthReqMessage(DataclassMessage, Message):
    type_str = "authr"

    n_client: int
    n_common: int
    sender: str
    reciever: str

'''
The ticket from a server to the 2 clients with ther shared session key
'''
@dataclass
class AuthTicketMessage(DataclassMessage, Message):
    type_str = "autht"

    n_client: int
    session_key: bytes
