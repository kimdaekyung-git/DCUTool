from __future__ import annotations

import enum
import queue
import socket
import threading
from typing import Callable, Optional

from .protocol import Frame, FrameDecoder, FrameEncoder, parse_frame
from .transport import Transport


class ClientState(enum.Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


StateCallback = Callable[[ClientState, Optional[str]], None]


class DcuTcpClient:
    """Threaded TCP client that exchanges framed packets with the DCU."""

    def __init__(
        self,
        *,
        on_frame: Optional[Callable[[Frame, Transport], None]] = None,
        on_state_change: Optional[StateCallback] = None,
        on_send_frame: Optional[Callable[[bytes, Transport], None]] = None,
        encoder: Optional[FrameEncoder] = None,
    ) -> None:
        self._encoder = encoder or FrameEncoder()
        self._decoder = FrameDecoder()
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._send_queue: "queue.Queue[bytes]" = queue.Queue()
        self._stop_event = threading.Event()
        self._state = ClientState.DISCONNECTED
        self._state_lock = threading.Lock()
        self._on_frame = on_frame
        self._on_state_change = on_state_change
        self._on_send_frame = on_send_frame

    @property
    def state(self) -> ClientState:
        with self._state_lock:
            return self._state

    def connect(self, host: str, port: int, *, timeout: float = 5.0) -> None:
        if self.state in {ClientState.CONNECTING, ClientState.CONNECTED}:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, args=(host, port, timeout), daemon=True)
        self._thread.start()

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._socket = None
        self._set_state(ClientState.DISCONNECTED)

    def send_frame(self, frame: bytes) -> None:
        if self.state != ClientState.CONNECTED:
            raise RuntimeError("client is not connected")
        if self._on_send_frame:
            self._on_send_frame(frame, self)
        self._send_queue.put_nowait(frame)

    def send_command(self, cmd: int, data: bytes = b"", **kwargs) -> None:
        frame = self._encoder.build(cmd, data, **kwargs)
        self.send_frame(frame)

    def _worker(self, host: str, port: int, timeout: float) -> None:
        self._set_state(ClientState.CONNECTING)
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(0.5)
            self._socket = sock
            self._decoder = FrameDecoder()
            self._set_state(ClientState.CONNECTED)
        except OSError as exc:
            self._set_state(ClientState.ERROR, str(exc))
            self._stop_event.set()
            return

        try:
            while not self._stop_event.is_set():
                try:
                    chunk = self._socket.recv(4096)
                    if not chunk:
                        break
                    for payload in self._decoder.feed(chunk):
                        try:
                            frame = parse_frame(payload)
                        except ValueError as exc:
                            self._set_state(ClientState.ERROR, str(exc))
                            continue
                        if self._on_frame:
                            self._on_frame(frame, self)
                except socket.timeout:
                    pass
                except OSError as exc:
                    self._set_state(ClientState.ERROR, str(exc))
                    break

                self._flush_send_queue()
        finally:
            try:
                if self._socket:
                    self._socket.close()
            finally:
                self._socket = None
                self._set_state(ClientState.DISCONNECTED)

    def _flush_send_queue(self) -> None:
        if not self._socket:
            return
        while True:
            try:
                frame = self._send_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._socket.sendall(frame)
            except OSError as exc:
                self._set_state(ClientState.ERROR, str(exc))
                break

    def _set_state(self, state: ClientState, info: Optional[str] = None) -> None:
        with self._state_lock:
            self._state = state
        if self._on_state_change:
            self._on_state_change(state, info)
