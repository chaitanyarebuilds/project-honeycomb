"""A tiny in-process SMTP server for tests: records messages, speaks just enough SMTP."""

import asyncio
import threading
from email import message_from_bytes
from email.message import Message


class FakeSMTP:
    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "FakeSMTP":
        self._thread.start()
        self._ready.wait(5)
        return self

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        server = self._loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        def reply(line: str) -> None:
            writer.write((line + "\r\n").encode())

        reply("220 fake smtp ready")
        data_mode, buffer = False, b""
        while not reader.at_eof():
            line = await reader.readline()
            if not line:
                break
            if data_mode:
                buffer += line
                if buffer.endswith(b"\r\n.\r\n"):
                    self.messages.append(message_from_bytes(buffer[:-5]))
                    data_mode, buffer = False, b""
                    reply("250 queued")
            else:
                cmd = line.decode().strip().upper()
                if cmd.startswith(("EHLO", "HELO")):
                    reply("250 localhost")
                elif cmd.startswith(("MAIL", "RCPT")):
                    reply("250 ok")
                elif cmd == "DATA":
                    data_mode = True
                    reply("354 go ahead")
                elif cmd == "QUIT":
                    reply("221 bye")
                    break
                else:
                    reply("250 ok")
            await writer.drain()
        writer.close()
