import sys
from message import *
from util import *
from node import *

PORT = 25154


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
                        Message.pack(
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
            tick_b: AuthTicketMessage = Message.unpack(u64(pauth3.k_b2)).decrypt(
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
                                    Message.pack(
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
                        tick_a: AuthTicketMessage = Message.unpack(
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
