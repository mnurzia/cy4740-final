import asyncio
import logging

from message import *

'''
A Node is any endpoint on the application
'''
class Node:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    '''
    Sets up the server for the node and starts the listenings
    '''
    async def start(self, *args):
        pass

    '''
    Sends an unencrypted message to a write stream
    '''
    def send_msg(self, writer: asyncio.StreamWriter, message: Message):
        writer.write(Message.pack(message))

    '''
    Receives an unencrypted message and types the input for ease of use
    '''
    async def receive_msg(self, reader: asyncio.StreamReader) -> Message:
        msg_length: int
        metadata: bytes = await reader.readexactly(Message.TYPE_LENGTH_FMT_SIZE)
        _, msg_length = struct.unpack(Message.TYPE_LENGTH_FMT, metadata)
        msg_bytes = await reader.readexactly(msg_length)
        return Message.unpack(metadata + msg_bytes)

    '''
    Sends out an encrypted message to a specified write stream
    '''
    def send_msg_encrypted(
        self, writer: asyncio.StreamWriter, message: Message, key: bytes
    ):
        self.send_msg(writer, EncryptedMessage.encrypt(key, message))

    '''
    Receives an encrypted message from a specified read stream and types it
    '''
    async def receive_msg_encrypted(
        self, reader: asyncio.StreamReader, key: bytes
    ) -> Message:
        msg: EncryptedMessage = await self.receive_msg(reader)
        assert isinstance(msg, EncryptedMessage)
        return msg.decrypt(key)
    
    '''
    Wraps up the use of a node and closes all open things
    '''
    async def finish(self):
        pass
