from __future__ import annotations

import enum
import queue
import socket
import threading
from typing import Callable, Optional, Tuple

from .protocol import Frame, FrameDecoder, FrameEncoder, parse_frame
from .transport import Transport


class ServerState(enum.Enum):
    STOPPED = "stopped"
    LISTENING = "listening"
    CONNECTED = "connected"
    ERROR = "error"


StateCallback = Callable[[ServerState, Optional[str]], None]
FrameCallback = Callable[[Frame, Transport], None]


class DcuTcpServer(Transport):
    """Single-connection TCP server that accepts DCU originated sessions."""

    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 0,
        on_frame: Optional[FrameCallback] = None,
        on_state_change: Optional[StateCallback] = None,
        encoder: Optional[FrameEncoder] = None,
        on_send_frame: Optional[Callable[[bytes, Transport], None]] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._on_frame = on_frame
        self._on_state_change = on_state_change
        self._encoder = encoder or FrameEncoder()
        self._on_send_frame = on_send_frame

        self._server_socket: Optional[socket.socket] = None
        self._client_socket: Optional[socket.socket] = None
        self._decoder = FrameDecoder()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._send_queue: "queue.Queue[bytes]" = queue.Queue()

        self._state = ServerState.STOPPED
        self._state_lock = threading.Lock()

    @property
    def bind(self) -> Tuple[str, int]:
        return self._host, self._port

    @property
    def state(self) -> ServerState:
        with self._state_lock:
            return self._state

    def configure(self, host: str, port: int) -> None:
        self._host = host
        self._port = port

    def start(self) -> None:
        if self.state != ServerState.STOPPED:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._server_socket.close()
            except OSError:
                pass
        if self._client_socket:
            try:
                self._client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._client_socket.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._client_socket = None
        self._server_socket = None
        self._set_state(ServerState.STOPPED)

    def send_command(self, cmd: int, data: bytes = b"", **kwargs) -> None:
        frame = self._encoder.build(cmd, data, **kwargs)
        self.send_frame(frame)

    def send_frame(self, frame: bytes) -> None:
        if self.state != ServerState.CONNECTED:
            raise RuntimeError("server connection is not active")
        if self._on_send_frame:
            self._on_send_frame(frame, self)
        self._send_queue.put_nowait(frame)

    # Internal helpers -------------------------------------------------
    def _serve(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self._host, self._port))
            srv.listen(1)
            srv.settimeout(0.5)
            self._server_socket = srv
            self._set_state(ServerState.LISTENING)
        except OSError as exc:
            self._set_state(ServerState.ERROR, str(exc))
            return

        while not self._stop_event.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop_event.is_set():
                    self._set_state(ServerState.ERROR, str(exc))
                break

            self._client_socket = client
            self._decoder = FrameDecoder()
            client.settimeout(0.5)
            self._set_state(ServerState.CONNECTED, f"{addr[0]}:{addr[1]}")

            try:
                while not self._stop_event.is_set():
                    try:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        for payload in self._decoder.feed(chunk):
                            try:
                                frame = parse_frame(payload)
                            except ValueError as exc:
                                self._set_state(ServerState.ERROR, str(exc))
                                continue
                            if self._on_frame:
                                self._on_frame(frame, self)
                    except socket.timeout:
                        pass
                    except OSError as exc:
                        self._set_state(ServerState.ERROR, str(exc))
                        break

                    self._flush_send_queue()
            finally:
                try:
                    client.close()
                except OSError:
                    pass
                self._client_socket = None
                if not self._stop_event.is_set():
                    self._set_state(ServerState.LISTENING)

        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        self._server_socket = None

    def _flush_send_queue(self) -> None:
        if not self._client_socket:
            return
        while True:
            try:
                frame = self._send_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._client_socket.sendall(frame)
            except OSError as exc:
                self._set_state(ServerState.ERROR, str(exc))
                break

    def _set_state(self, state: ServerState, info: Optional[str] = None) -> None:
        with self._state_lock:
            self._state = state
        if self._on_state_change:
            self._on_state_change(state, info)


__all__ = [
    "DcuTcpServer",
    "ServerState",
]
