"""Modular architecture for the 통합검침 시스템 프로그램.

이 모듈은 개발지시문.md에서 정의한 아키텍처 요구사항을 충족하기 위한
구성요소(FEP 서버, DCU 제어, 데이터 수집/저장, 운영 API)를 제공합니다.

각 구성요소는 독립적으로 사용할 수 있으며, `IntegratedMeteringSystem`을
통해 통합 실행도 가능합니다.
"""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from dcutools import (
    Command,
    DcuTcpClient,
    DcuTcpServer,
    Frame,
    PacketParser,
    Transport,
)
from dcutools.protocol import build_rmu_id

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session & parser helpers


class SessionManager:
    """Track active DCU sessions keyed by DID/SID."""

    def __init__(self) -> None:
        self._sessions: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def update(self, did: Optional[int], sid: Optional[int], **info: Any) -> None:
        if did is None or sid is None:
            return
        key = (did, sid)
        with self._lock:
            session = self._sessions.setdefault(key, {"did": did, "sid": sid})
            session.update(info)
            session["updated_at"] = time.time()

    def get(self, did: int, sid: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get((did, sid))

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(value) for value in self._sessions.values()]

    def latest(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self._sessions:
                return None
            key = max(self._sessions, key=lambda k: self._sessions[k].get("updated_at", 0.0))
            return dict(self._sessions[key])


class FrameParser:
    """Wrapper over :class:`PacketParser` with safe error handling."""

    def __init__(self) -> None:
        self._parser = PacketParser()

    def parse(self, frame: Frame) -> Dict[str, Any]:
        try:
            return self._parser.parse(frame)
        except Exception as exc:  # noqa: BLE001
            log.exception("Packet parsing failed: %s", exc)
            return {"error": str(exc), "raw_data": frame.data.hex()}


# ---------------------------------------------------------------------------
# Command dispatcher


class CommandDispatcher:
    """Route frames to command-specific callbacks."""

    def __init__(self) -> None:
        self._handlers: Dict[int, List[Callable[[Frame, Dict[str, Any], Transport], None]]] = {}

    def register(self, command: Command | int, handler: Callable[[Frame, Dict[str, Any], Transport], None]) -> None:
        code = int(command)
        self._handlers.setdefault(code, []).append(handler)

    def dispatch(self, frame: Frame, parsed: Dict[str, Any], transport: Transport) -> None:
        for handler in self._handlers.get(frame.cmd, []):
            try:
                handler(frame, parsed, transport)
            except Exception:  # noqa: BLE001
                log.exception("Command handler failed for 0x%02X", frame.cmd)


# ---------------------------------------------------------------------------
# FEP server component


class FepServer:
    """TCP listener accepting DCU-originated connections."""

    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 9008,
        parser: Optional[FrameParser] = None,
        session_manager: Optional[SessionManager] = None,
        dispatcher: Optional[CommandDispatcher] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.parser = parser or FrameParser()
        self.session_manager = session_manager or SessionManager()
        self.dispatcher = dispatcher or CommandDispatcher()

        self._server = DcuTcpServer(
            on_frame=self._handle_frame,
            on_state_change=self._handle_state,
            on_send_frame=self._handle_send,
        )
        self._frame_listeners: List[Callable[[Frame, Dict[str, Any], Transport], None]] = []
        self._state_listeners: List[Callable[[str, Optional[str]], None]] = []
        self._send_listeners: List[Callable[[bytes, Transport], None]] = []

    def start(self) -> None:
        self._server.configure(self.host, self.port)
        self._server.start()
        log.info("FEP server listening on %s:%s", self.host, self.port)

    def stop(self) -> None:
        self._server.stop()
        log.info("FEP server stopped")

    # Listener registration -------------------------------------------------
    def on_frame(self, callback: Callable[[Frame, Dict[str, Any], Transport], None]) -> None:
        self._frame_listeners.append(callback)

    def on_state(self, callback: Callable[[str, Optional[str]], None]) -> None:
        self._state_listeners.append(callback)

    def on_send(self, callback: Callable[[bytes, Transport], None]) -> None:
        self._send_listeners.append(callback)

    # Command helpers -------------------------------------------------------
    def send_command(
        self,
        command: Command | int,
        data: bytes = b"",
        *,
        did: Optional[int] = None,
        sid: Optional[int] = None,
    ) -> None:
        target = self.session_manager.latest()
        did_val = did if did is not None else (target or {}).get("did", 0)
        sid_val = sid if sid is not None else (target or {}).get("sid", did_val)
        if did_val is None:
            raise RuntimeError("No active session for FEP command transmission")
        self._server.send_command(int(command), data, did=int(did_val), sid=int(sid_val))

    # Internal callbacks ----------------------------------------------------
    def _handle_frame(self, frame: Frame, transport: Transport) -> None:
        parsed = self.parser.parse(frame)
        self.session_manager.update(frame.did, frame.sid, last_command=frame.cmd, last_payload=parsed)
        self.dispatcher.dispatch(frame, parsed, transport)
        for callback in self._frame_listeners:
            callback(frame, parsed, transport)

    def _handle_state(self, state, info: Optional[str]) -> None:
        state_value = getattr(state, "value", str(state))
        for callback in self._state_listeners:
            callback(state_value, info)

    def _handle_send(self, payload: bytes, transport: Transport) -> None:
        for callback in self._send_listeners:
            callback(payload, transport)


# ---------------------------------------------------------------------------
# DCU control module


class DcuController:
    """Client-side connector for issuing requests to DCU endpoints."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        default_dcu_id: int = 0,
        session_manager: Optional[SessionManager] = None,
        fep_server: Optional[FepServer] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.default_dcu_id = default_dcu_id
        self.session_manager = session_manager or SessionManager()
        self.fep_server = fep_server

        self._client = DcuTcpClient(
            on_frame=self._handle_frame,
            on_state_change=self._handle_state,
        )
        self._parser = FrameParser()
        self._events: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

    # Connection ------------------------------------------------------------
    def connect(self) -> None:
        self._client.connect(self.host, self.port)

    def disconnect(self) -> None:
        self._client.disconnect()

    # Command helpers -------------------------------------------------------
    def request_dcu_info(self, did: Optional[int] = None) -> None:
        did_val = did if did is not None else self.default_dcu_id
        sid_val = did_val
        self._client.send_command(Command.DCU_INFO_REQUEST, b"", did=did_val, sid=sid_val)

    def request_rmu_info(self, rcu: int, tcu: int, *, did: Optional[int] = None) -> None:
        did_val = did if did is not None else self.default_dcu_id
        payload = build_rmu_id(rcu, tcu)
        sid_val = did_val
        self._client.send_command(Command.RMU_INFO_REQUEST, payload, did=did_val, sid=sid_val)

    def request_current_reading(self, rcu: int, tcu: int, *, did: Optional[int] = None) -> None:
        did_val = did if did is not None else self.default_dcu_id
        payload = build_rmu_id(rcu, tcu)
        sid_val = did_val
        self._client.send_command(Command.CURRENT_READING_REQUEST, payload, did=did_val, sid=sid_val)

    def request_periodic_reading(self, rcu: int, tcu: int, *, did: Optional[int] = None) -> None:
        did_val = did if did is not None else self.default_dcu_id
        payload = build_rmu_id(rcu, tcu)
        sid_val = did_val
        self._client.send_command(Command.PERIODIC_READING_REQUEST, payload, did=did_val, sid=sid_val)

    def send_via_fep(self, command: Command | int, data: bytes = b"", *, did: Optional[int] = None, sid: Optional[int] = None) -> None:
        if not self.fep_server:
            raise RuntimeError("FEP server reference is not configured")
        self.fep_server.send_command(command, data, did=did, sid=sid)

    # Event polling ---------------------------------------------------------
    def poll_events(self) -> List[Tuple[str, Any]]:
        items: List[Tuple[str, Any]] = []
        while True:
            try:
                items.append(self._events.get_nowait())
            except queue.Empty:
                break
        return items

    # Internal callbacks ----------------------------------------------------
    def _handle_frame(self, frame: Frame, transport: Transport) -> None:
        parsed = self._parser.parse(frame)
        self.session_manager.update(frame.did, frame.sid, last_client_command=frame.cmd)
        self._events.put(("frame", {"frame": frame, "parsed": parsed}))

    def _handle_state(self, state, info: Optional[str]) -> None:
        state_value = getattr(state, "value", str(state))
        self._events.put(("state", {"state": state_value, "info": info}))


# ---------------------------------------------------------------------------
# Data storage


class DataStore:
    """Abstract interface for persisting readings and events."""

    def save_login(self, dcu_id: int, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    def save_meter_reading(self, dcu_id: int, rmu_id: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    def save_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    def fetch_recent_readings(self, limit: int = 100) -> List[Dict[str, Any]]:
        raise NotImplementedError


class SqliteDataStore(DataStore):
    """SQLite-backed persistence layer."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
        self._ensure_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _ensure_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dcu_id INTEGER,
                    firmware TEXT,
                    ip TEXT,
                    port INTEGER,
                    raw JSON,
                    created_at TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meter_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dcu_id INTEGER,
                    rmu_id TEXT,
                    meter_type TEXT,
                    value TEXT,
                    unit TEXT,
                    raw JSON,
                    measured_at TEXT,
                    created_at TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    raw JSON,
                    created_at TEXT
                )
                """
            )

    def save_login(self, dcu_id: int, payload: Dict[str, Any]) -> None:
        record = {
            "dcu_id": dcu_id,
            "firmware": payload.get("firmware_version"),
            "ip": payload.get("dcu_ip"),
            "port": payload.get("dcu_port"),
            "raw": json.dumps(payload, default=str, ensure_ascii=False),
            "created_at": datetime.utcnow().isoformat(),
        }
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO login_history(dcu_id, firmware, ip, port, raw, created_at)
                VALUES(:dcu_id, :firmware, :ip, :port, :raw, :created_at)
                """,
                record,
            )

    def save_meter_reading(self, dcu_id: int, rmu_id: str, payload: Dict[str, Any]) -> None:
        measured_at = payload.get("timestamp")
        dumps = payload.get("dumps", [])
        created_at = datetime.utcnow().isoformat()
        rows = []
        for dump in dumps:
            meter_type = dump.get("meter_type")
            if isinstance(meter_type, list):
                meter_type = ",".join(meter_type)
            interpreted = dump.get("interpreted") or {}
            value = interpreted.get("value") if isinstance(interpreted, dict) else None
            unit = interpreted.get("unit") if isinstance(interpreted, dict) else None
            rows.append(
                (
                    dcu_id,
                    rmu_id,
                    meter_type,
                    json.dumps(value, ensure_ascii=False),
                    unit,
                    json.dumps(dump, default=str, ensure_ascii=False),
                    str(measured_at),
                    created_at,
                )
            )
        if not rows:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                """
                INSERT INTO meter_readings(
                    dcu_id, rmu_id, meter_type, value, unit, raw, measured_at, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        record = {
            "event_type": event_type,
            "raw": json.dumps(payload, default=str, ensure_ascii=False),
            "created_at": datetime.utcnow().isoformat(),
        }
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO events(event_type, raw, created_at) VALUES(:event_type, :raw, :created_at)",
                record,
            )

    def fetch_recent_readings(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                SELECT dcu_id, rmu_id, meter_type, value, unit, raw, measured_at, created_at
                FROM meter_readings
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Data collector


class DataCollector:
    """Persist incoming frames into the datastore."""

    def __init__(self, store: DataStore, sessions: SessionManager) -> None:
        self.store = store
        self.sessions = sessions

    def process_frame(self, frame: Frame, parsed: Dict[str, Any], _transport: Transport) -> None:
        if frame.cmd == Command.DCU_INFO_RESPONSE:
            dcu_id = frame.sid if frame.sid is not None else frame.did
            self.store.save_login(int(dcu_id or 0), parsed)
        elif frame.cmd in {
            Command.PERIODIC_READING_RESPONSE,
            Command.CURRENT_READING_RESPONSE,
            Command.SAVED_READING_RESPONSE,
        }:
            rmu = parsed.get("rmu_id")
            if isinstance(rmu, dict):
                rcu = rmu.get("rcu")
                tcu = rmu.get("tcu")
                rmu_label = f"{rcu}-{tcu}" if rcu is not None and tcu is not None else json.dumps(rmu)
            else:
                rmu_label = str(rmu)
            self.store.save_meter_reading(int(frame.sid or frame.did or 0), rmu_label, parsed)
        elif frame.cmd in {Command.EVENT_NOTIFICATION, Command.NACK}:
            self.store.save_event(Command(frame.cmd).name, parsed)


# ---------------------------------------------------------------------------
# REST-like API server (standard library implementation)


class ApiServer:
    """Threaded HTTP server exposing operational APIs."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8080,
        sessions: Optional[SessionManager] = None,
        data_store: Optional[DataStore] = None,
        dcu_controller: Optional[DcuController] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.sessions = sessions or SessionManager()
        self.data_store = data_store
        self.dcu_controller = dcu_controller
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._server is not None:
            return

        server = ThreadingHTTPServer((self.host, self.port), self._build_handler())
        server.daemon_threads = True

        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="ApiServer", daemon=True)
        self._thread.start()
        log.info("API server started on http://%s:%s", self.host, self.port)

    def stop(self) -> None:
        if not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None
        log.info("API server stopped")

    # Handler ----------------------------------------------------------------
    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        sessions = self.sessions
        store = self.data_store
        controller = self.dcu_controller

        class RequestHandler(BaseHTTPRequestHandler):
            server_version = "IntegratedMeteringAPI/1.0"

            def _json_response(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
                body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                if self.path == "/status":
                    self._json_response({
                        "sessions": sessions.all(),
                        "recent_readings": store.fetch_recent_readings(20) if store else [],
                    })
                else:
                    self._json_response({"error": "unknown endpoint"}, HTTPStatus.NOT_FOUND)

            def do_POST(self) -> None:  # noqa: N802
                content_length = int(self.headers.get("Content-Length") or 0)
                raw_data = self.rfile.read(content_length) if content_length else b"{}"
                try:
                    payload = json.loads(raw_data.decode("utf-8")) if raw_data else {}
                except json.JSONDecodeError:
                    self._json_response({"error": "invalid JSON payload"}, HTTPStatus.BAD_REQUEST)
                    return

                if self.path == "/commands/current-reading":
                    if not controller:
                        self._json_response({"error": "DCU controller unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
                        return
                    try:
                        rcu = int(payload.get("rcu"))
                        tcu = int(payload.get("tcu"))
                    except (TypeError, ValueError):
                        self._json_response({"error": "rcu/tcu must be integers"}, HTTPStatus.BAD_REQUEST)
                        return
                    controller.request_current_reading(rcu, tcu)
                    self._json_response({"status": "accepted"})
                elif self.path == "/commands/rmu-info":
                    if not controller:
                        self._json_response({"error": "DCU controller unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
                        return
                    try:
                        rcu = int(payload.get("rcu"))
                        tcu = int(payload.get("tcu"))
                    except (TypeError, ValueError):
                        self._json_response({"error": "rcu/tcu must be integers"}, HTTPStatus.BAD_REQUEST)
                        return
                    controller.request_rmu_info(rcu, tcu)
                    self._json_response({"status": "accepted"})
                else:
                    self._json_response({"error": "unknown endpoint"}, HTTPStatus.NOT_FOUND)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - matches signature
                log.debug("API %s - %s", self.address_string(), format % args)

        return RequestHandler


# ---------------------------------------------------------------------------
# Integrated system orchestrator


@dataclass
class SystemConfig:
    """Runtime configuration values derived from ini/json files."""

    fep_host: str = "0.0.0.0"
    fep_port: int = 9008
    dcu_host: str = "127.0.0.1"
    dcu_port: int = 15000
    dcu_id: int = 0
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    db_path: Path = Path("data/metering.sqlite3")


class IntegratedMeteringSystem:
    """Coordinates all modules into a ready-to-run system."""

    def __init__(
        self,
        config: Optional[SystemConfig] = None,
        *,
        data_store: Optional[DataStore] = None,
    ) -> None:
        self.config = config or SystemConfig()
        self.sessions = SessionManager()
        self.parser = FrameParser()
        self.dispatcher = CommandDispatcher()
        self.data_store = data_store or SqliteDataStore(self.config.db_path)

        self.fep_server = FepServer(
            host=self.config.fep_host,
            port=self.config.fep_port,
            parser=self.parser,
            session_manager=self.sessions,
            dispatcher=self.dispatcher,
        )
        self.dcu_controller = DcuController(
            self.config.dcu_host,
            self.config.dcu_port,
            default_dcu_id=self.config.dcu_id,
            session_manager=self.sessions,
            fep_server=self.fep_server,
        )
        self.data_collector = DataCollector(self.data_store, self.sessions)
        self.api_server = ApiServer(
            host=self.config.api_host,
            port=self.config.api_port,
            sessions=self.sessions,
            data_store=self.data_store,
            dcu_controller=self.dcu_controller,
        )

        self.fep_server.on_frame(self.data_collector.process_frame)

        # Register dispatcher defaults (expandable)
        self.dispatcher.register(Command.DCU_INFO_RESPONSE, self.data_collector.process_frame)
        self.dispatcher.register(Command.PERIODIC_READING_RESPONSE, self.data_collector.process_frame)
        self.dispatcher.register(Command.CURRENT_READING_RESPONSE, self.data_collector.process_frame)
        self.dispatcher.register(Command.SAVED_READING_RESPONSE, self.data_collector.process_frame)
        self.dispatcher.register(Command.EVENT_NOTIFICATION, self.data_collector.process_frame)

    # Lifecycle --------------------------------------------------------------
    def start(self) -> None:
        self.fep_server.start()
        self.dcu_controller.connect()
        self.api_server.start()
        log.info("Integrated metering system started")

    def stop(self) -> None:
        self.api_server.stop()
        self.dcu_controller.disconnect()
        self.fep_server.stop()
        if isinstance(self.data_store, SqliteDataStore):
            self.data_store.close()
        log.info("Integrated metering system stopped")

    # Convenience -----------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        return {
            "config": {
                "fep_host": self.config.fep_host,
                "fep_port": self.config.fep_port,
                "dcu_host": self.config.dcu_host,
                "dcu_port": self.config.dcu_port,
                "dcu_id": self.config.dcu_id,
                "api_host": self.config.api_host,
                "api_port": self.config.api_port,
                "db_path": str(self.config.db_path),
            },
            "sessions": self.sessions.all(),
            "recent_readings": self.data_store.fetch_recent_readings(10),
        }


__all__ = [
    "ApiServer",
    "CommandDispatcher",
    "DataCollector",
    "DataStore",
    "DcuController",
    "FepServer",
    "FrameParser",
    "IntegratedMeteringSystem",
    "SessionManager",
    "SqliteDataStore",
    "SystemConfig",
]
