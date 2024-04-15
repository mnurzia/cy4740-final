import asyncio
from typing import Optional
from passdb import load_pdb
from util import *
from message import *
from node import *

"""
A server endpoint in the application
"""


class Server(Node):
    def __init__(self, host: Host, pdb: str):
        super().__init__("server")
        self.server: asyncio.Server = asyncio.start_server(
            self._client, str(host.address), host.port
        )
        self.clients = {}
        self.keys = {}
        self.pdb = load_pdb(pdb)

    async def start(self, *args) -> asyncio.Server:
        self.server = await self.server
        return await self.server.serve_forever()

    """
    The asynchronous handling of incoming clients and their continued communication until they log off
    """

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        identity: Optional[str] = None
        try:
            # Client/Server Authentication
            auth1: Auth1Message = await self.receive_msg(reader)
            assert isinstance(auth1, Auth1Message)
            receiver = int.from_bytes(os.urandom(2048 // 8), "big")
            salt, f_w = self.pdb[auth1.identity]
            f_w = int.from_bytes(f_w, "big")
            g_bfw = (pow(G, receiver, P) + pow(G, f_w, P)) % P
            u = int.from_bytes(os.urandom(2048 // 8), "big")
            c1 = os.urandom(2048 // 8)
            self.send_msg(
                writer,
                Auth2Message(g_bfw, u, c1, salt),
            )
            client_key = hkdf(
                (pow(auth1.dh_mask, receiver, P) * pow(pow(G, f_w, P), receiver * u, P))
                % P
            )
            auth3: Auth3Message = await self.receive_msg(reader)
            assert isinstance(auth3, Auth3Message)
            assert auth_decrypt(client_key, auth3.resp_1) == c1
            self.send_msg(
                writer, Auth4Message(auth_encrypt(client_key, auth3.challenge_2))
            )

            # Post Authentication and receiving of a listening port for the client
            client_port_msg: PeerPortMessage = await self.receive_msg_encrypted(
                reader, client_key
            )
            assert isinstance(client_port_msg, PeerPortMessage)
            client_ip = writer.get_extra_info("peername")[0]
            self.clients[identity := auth1.identity] = (
                f"{client_ip}:{client_port_msg.peer_port}"
            )
            assert identity not in self.keys
            self.keys[identity] = client_key
            self.logger.info(f"Authenticated to client {identity}")

            # The listening for communication from a client
            while (
                message := await self.receive_msg_encrypted(reader, client_key)
            ) != None:
                match message:
                    case ClientsRequestMessage():
                        # The request for the list of logged on users from a client
                        self.send_msg_encrypted(
                            writer, ClientsResponseMessage(self.clients), client_key
                        )
                    case PeerAuth2Message(
                        sender, receiver, cipher_sender, cipher_receiver
                    ):
                        # The authentication of an initiating client
                        auth_sender: AuthReqMessage = Message.unpack(
                            cipher_sender
                        ).decrypt(self.keys[sender])
                        assert isinstance(auth_sender, AuthReqMessage)
                        assert (
                            auth_sender.sender == sender
                            and auth_sender.reciever == receiver
                        )

                        auth_receiver: AuthReqMessage = Message.unpack(
                            cipher_receiver
                        ).decrypt(self.keys[receiver])
                        assert isinstance(auth_receiver, AuthReqMessage)
                        assert (
                            auth_receiver.sender == sender
                            and auth_receiver.reciever == receiver
                        )

                        # The creation of a common key post authentication that the communication thus far is secure
                        assert auth_sender.n_common == auth_receiver.n_common
                        k_shared: bytes = os.urandom(32)
                        self.send_msg_encrypted(
                            writer,
                            PeerAuth3Message(
                                auth_sender.n_common,
                                Message.pack(
                                    EncryptedMessage.encrypt(
                                        self.keys[sender],
                                        AuthTicketMessage(
                                            auth_sender.n_client, k_shared
                                        ),
                                    )
                                ),
                                EncryptedMessage.pack(
                                    EncryptedMessage.encrypt(
                                        self.keys[receiver],
                                        AuthTicketMessage(
                                            auth_receiver.n_client, k_shared
                                        ),
                                    )
                                ),
                            ),
                            client_key,
                        )
                    case LogoutMessage():
                        # The handling of a log out request from a client
                        self.logger.info(f"Client {identity} logged out")
                        writer.close()
                        break
                    case _:
                        raise Exception("unexpected message: ", repr(message))
        except asyncio.CancelledError:
            # server closing
            self.logger.info(f"Logging out client {identity}")
            self.send_msg_encrypted(writer, LogoutMessage(), client_key)
            pass
        except Exception as e:
            self.logger.exception(e)
            writer.write_eof()
        if identity:
            del self.clients[identity]
            del self.keys[identity]

    async def finish(self):
        self.server.close()
