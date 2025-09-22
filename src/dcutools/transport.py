from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    """Common interface for sending framed packets back to the DCU."""

    def send_command(self, cmd: int, data: bytes = b"", **kwargs) -> None:
        ...

    def send_frame(self, frame: bytes) -> None:
        ...


__all__ = ["Transport"]
