import asyncio
import logging

from message import *


class Node:

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    async def start(self, *args):
        pass

    def send_msg(self, writer: asyncio.StreamWriter, message: Message):
        writer.write(Message.pack(message))

    async def receive_msg(self, reader: asyncio.StreamReader) -> Message:
        msg_length: int
        metadata: bytes = await reader.readexactly(Message.TYPE_LENGTH_FMT_SIZE)
        _, msg_length = struct.unpack(Message.TYPE_LENGTH_FMT, metadata)
        msg_bytes = await reader.readexactly(msg_length)
        return Message.unpack(metadata + msg_bytes)

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
    
    async def finish(self):
        pass
