import asyncio
from typing import Optional
from passdb import load_pdb
from util import *
from message import *
from node import *


class Server(Node):

    def __init__(self, host: Host, pdb: str):
        super().__init__("server")
        self.server = asyncio.start_server(self._client, str(host.address), host.port)
        self.clients = {}
        self.keys = {}
        self.pdb = load_pdb(pdb)

    async def start(self) -> asyncio.Server:
        return await self.server

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        identity: Optional[str] = None
        try:
            auth1: Auth1Message = await self.receive_msg(reader)
            assert isinstance(auth1, Auth1Message)
            b = int.from_bytes(os.urandom(2048 // 8))
            salt, f_w = self.pdb[auth1.identity]
            f_w = int.from_bytes(f_w)
            g_bfw = (pow(G, b, P) + pow(G, f_w, P)) % P
            u = int.from_bytes(os.urandom(2048 // 8))
            c1 = os.urandom(2048 // 8)
            self.send_msg(
                writer,
                Auth2Message(g_bfw, u, c1, salt),
            )
            k_a = hkdf((pow(auth1.dh, b, P) * pow(pow(G, f_w, P), b * u, P)) % P)
            auth3: Auth3Message = await self.receive_msg(reader)
            assert isinstance(auth3, Auth3Message)
            assert ad(k_a, auth3.ka_c1) == c1
            self.send_msg(writer, Auth4Message(ae(k_a, auth3.c2)))

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
                        a1: AuthReqMessage = Message.unpack(k_a1).decrypt(self.keys[a])
                        assert isinstance(a1, AuthReqMessage)
                        assert a1.a == a and a1.b == b
                        b1: AuthReqMessage = Message.unpack(k_b1).decrypt(self.keys[b])
                        assert isinstance(b1, AuthReqMessage)
                        assert b1.a == a and b1.b == b
                        assert a1.n_2 == b1.n_2
                        k_ab: bytes = os.urandom(32)
                        self.send_msg_encrypted(
                            writer,
                            PeerAuth3Message(
                                a1.n_2,
                                Message.pack(
                                    EncryptedMessage.encrypt(
                                        self.keys[a],
                                        AuthTicketMessage(a1.n_1, k_ab),
                                    )
                                ),
                                EncryptedMessage.pack(
                                    EncryptedMessage.encrypt(
                                        self.keys[b],
                                        AuthTicketMessage(b1.n_1, k_ab),
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
