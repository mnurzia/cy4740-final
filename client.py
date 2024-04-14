import asyncio
import sys
from message import *
from util import *
from node import *
import random
import signal

PORT = 25154


class Client(Node):
    def __init__(self, host: Host, id: str):
        super().__init__("client")
        self.host = host
        self.port = random.randint(1024, 5000)
        self.client_key: bytes = b""
        self.clients = {}
        self.me: str = id
        self.server_reader: asyncio.StreamReader = None
        self.server_writer: asyncio.StreamWriter= None
        self.logger.debug(f'Username: {self.me}')

    async def connect_stdin(self) -> asyncio.StreamReader:
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        return reader

    async def start(self, pwd: str):
        self.peer = asyncio.start_server(self._peer, str(self.host.address), self.port)
        return await asyncio.gather(
            (await self.peer).serve_forever(), self._server(pwd)
        )

    async def _peer(self, peer_reader: asyncio.StreamReader, peer_writer: asyncio.StreamWriter):
        try:
            peer_init_comm: PeerAuth1Message = await self.receive_msg(peer_reader)
            assert isinstance(peer_init_comm, PeerAuth1Message)
            n_receiver = int.from_bytes(os.urandom(16), "big")
            self.send_msg_encrypted(
                self.server_writer,
                PeerAuth2Message(
                    peer_init_comm.sender,
                    self.me,
                    peer_init_comm.auth_sender,
                    Message.pack(
                        EncryptedMessage.encrypt(
                            self.client_key,
                            AuthReqMessage(n_receiver, peer_init_comm.n_common, peer_init_comm.sender, self.me),
                        )
                    ),
                ),
                self.client_key,
            )

            session_keys: PeerAuth3Message = await self.receive_msg_encrypted(
                self.server_reader, self.client_key
            )

            assert session_keys.n_common == peer_init_comm.n_common
            assert isinstance(session_keys, PeerAuth3Message)

            tick_recv: AuthTicketMessage = Message.unpack(session_keys.receiver_session).decrypt(self.client_key)
            assert isinstance(tick_recv, AuthTicketMessage)
            assert tick_recv.n_client == n_receiver

            session_key = tick_recv.session_key

            self.send_msg(peer_writer, PeerAuth4Message(session_keys.sender_session))

            peer_cipher: PeerAuth5Message = await self.receive_msg(peer_reader)
            assert isinstance(peer_cipher, PeerAuth5Message)

            print(f"message from {peer_init_comm.sender}: {ad(session_key, peer_cipher.cipher).decode()}")

            peer_writer.close()

        except Exception as e:
            self.logger.exception(e)

    async def _server(self, pwd: str):
        self.server_reader, self.server_writer = await asyncio.open_connection(
            str(self.host.address), self.host.port
        )
        a = int.from_bytes(os.urandom(2048 // 8), "big")
        self.send_msg(self.server_writer, Auth1Message(self.me, pow(G, a, P)))
        auth2: Auth2Message = await self.receive_msg(self.server_reader)
        assert isinstance(auth2, Auth2Message)

        pw_hash = int.from_bytes(scrypt(auth2.salt, pwd.encode()), "big")
        g_b = (auth2.dh_masked_pw - pow(G, pw_hash, P)) % P
        client_key = hkdf(pow(g_b, a + auth2.nonce * pw_hash, P))
        c2 = os.urandom(2048 // 8)
        self.send_msg(self.server_writer, Auth3Message(ae(client_key, auth2.challenge_1), c2))
        auth4: Auth4Message = await self.receive_msg(self.server_reader)
        assert isinstance(auth4, Auth4Message)
        assert ad(client_key, auth4.resp_2) == c2
        self.send_msg_encrypted(self.server_writer, PeerPortMessage(self.port), client_key)
        self.client_key = client_key
        self.logger.info("Authenticated to server")

        stdin = await self.connect_stdin()

        while True:
            cmd = (await stdin.readline()).decode()
            try:
                match cmd.split():
                    case ["list"]:
                        await self._update_clients()
                        for user, host in self.clients.items():
                            print(user, "-", host)
                    case ["send", peer, *msg]:
                        await self._update_clients()
                        if peer not in self.clients:
                            raise Exception(f"peer not found: {peer}")
                        peer_ip, peer_port = tuple(self.clients[peer].split(":"))
                        peer_read, peer_write = await asyncio.open_connection(
                            peer_ip, int(peer_port)
                        )
                        n_sender = int.from_bytes(os.urandom(16), "big")
                        n_common = int.from_bytes(os.urandom(16), "big")
                        self.send_msg(
                            peer_write,
                            PeerAuth1Message(
                                n_common,
                                self.me,
                                peer,
                                Message.pack(
                                    EncryptedMessage.encrypt(
                                        self.client_key,
                                        AuthReqMessage(n_sender, n_common, self.me, peer),
                                    )
                                ),
                            ),
                        )
                        pauth4: PeerAuth4Message = await self.receive_msg(peer_read)
                        assert isinstance(pauth4, PeerAuth4Message)
                        # rename this to be clearer
                        tick_a: AuthTicketMessage = Message.unpack(pauth4.sender_session).decrypt(
                            self.client_key
                        )
                        assert isinstance(tick_a, AuthTicketMessage)
                        assert tick_a.n_client == n_sender
                        k_ab = tick_a.session_key
                        self.send_msg(
                            peer_write,
                            PeerAuth5Message(ae(k_ab, " ".join(msg).encode())),
                        )
                    case _:
                        raise Exception(f"unexpected command: {cmd}")
            except Exception as e:
                self.logger.exception(e)

    async def _update_clients(self):
        self.send_msg_encrypted(self.server_writer, ClientsRequestMessage(), self.client_key)
        resp: ClientsResponseMessage = await self.receive_msg_encrypted(
            self.server_reader, self.client_key
        )
        assert isinstance(resp, ClientsResponseMessage)
        self.clients = resp.clients

    def finish(self):
        # TODO: signout and close connection
        if self.server_writer != None:
            self.server_writer.close()
