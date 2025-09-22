from __future__ import annotations

import argparse
import configparser
import ipaddress
import queue
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from dcutools import (
    ClientState,
    Command,
    DcuTcpClient,
    DcuTcpServer,
    Frame,
    PacketParser,
    ServerState,
    Transport,
)
from dcutools.protocol import EOF, SOF, apply_dle, decode_meter_type, pack_datetime


class ServiceMode:
    def __init__(self, settings_path: Path) -> None:
        self.settings_path = settings_path
        self.base_path = self.settings_path.resolve().parent
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._ensure_config_exists()
        self.settings = self._load_settings()
        self.packet_parser = PacketParser()
        self.client = DcuTcpClient(
            on_frame=self._handle_frame,
            on_state_change=self._handle_client_state,
            on_send_frame=self._handle_sent_frame,
        )
        self.server = DcuTcpServer(
            on_frame=self._handle_frame,
            on_state_change=self._handle_server_state,
            on_send_frame=self._handle_sent_frame,
        )
        self.sessions: Dict[Tuple[str, object], Dict[str, object]] = {}
        self.server_session_token: Optional[object] = None
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.data_log_path: Optional[Path] = None
        self.running = True
        self._reconnect_at: Optional[float] = None
        self._pending_initial_request = False
        self._restart_server_at: Optional[float] = None

    def run(self) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        fep_port = self.settings.get("fep_port", 9008)
        self.server.configure("0.0.0.0", fep_port)
        self.server.start()
        self._connect_client()

        while self.running:
            self._process_events()
            self._maybe_send_initial()
            self._maybe_reconnect()
            self._maybe_restart_server()
            time.sleep(0.1)

        self.client.disconnect()
        self.server.stop()

    def _connect_client(self) -> None:
        host = self.settings.get("host", "127.0.0.1")
        port = self.settings.get("port", 15000)
        self._log_text(f"CONNECT client -> {host}:{port}")
        self.client.connect(host, port)

    # ------------------------------------------------------------------
    # Event handlers

    def _handle_frame(self, frame: Frame, transport: Transport) -> None:
        self.events.put(("frame", frame, transport))

    def _handle_sent_frame(self, frame_bytes: bytes, transport: Transport) -> None:
        self.events.put(("sent", frame_bytes))

    def _handle_client_state(self, state: ClientState, info: Optional[str]) -> None:
        self.events.put(("client_state", state, info))

    def _handle_server_state(self, state: ServerState, info: Optional[str]) -> None:
        self.events.put(("server_state", state, info))

    # ------------------------------------------------------------------
    def _process_events(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            kind = event[0]
            if kind == "frame":
                self._process_frame(event[1], event[2])
            elif kind == "sent":
                self._log_data("SEND", event[1])
            elif kind == "client_state":
                self._process_client_state(event[1], event[2])
            elif kind == "server_state":
                self._process_server_state(event[1], event[2])

    def _process_frame(self, frame: Frame, transport: Transport) -> None:
        frame_bytes = bytes([SOF]) + apply_dle(frame.raw) + bytes([EOF])
        self._log_data("RECV", frame_bytes)

        try:
            parsed = self.packet_parser.parse(frame)
        except Exception as exc:  # noqa: BLE001
            self._log_text(f"ERROR parsing frame: {exc}")
            return

        session = self._get_session(transport)
        if frame.sid:
            session["dcu_id"] = frame.sid
        session["fep_id"] = frame.did

        if frame.cmd == Command.DCU_INFO_RESPONSE:
            session["dcu_info_data"] = frame.data
            self._log_login_info(frame, parsed)
            self._maybe_send_dcu_config(frame, transport, session)
        if frame.cmd == Command.RMU_INFO_RESPONSE and parsed.get("items"):
            for item in parsed["items"]:
                rmu = item.get("rmu_id")
                if isinstance(rmu, dict):
                    rcu = rmu.get("rcu")
                    tcu = rmu.get("tcu")
                    if isinstance(rcu, int) and isinstance(tcu, int):
                        session.setdefault("rmu_info", {})[(rcu, tcu)] = item
        if frame.cmd in {
            Command.PERIODIC_READING_RESPONSE,
            Command.CURRENT_READING_RESPONSE,
            Command.SAVED_READING_RESPONSE,
        }:
            self._update_rmu_table_cache(session, parsed)

        self._log_parsed_info(frame, parsed)

        if self.settings.get("auto_ack", True):
            self._auto_ack(frame, transport, session)

    def _process_client_state(self, state: ClientState, info: Optional[str]) -> None:
        detail = state.value if info is None else f"{state.value} ({info})"
        self._log_text(f"CLIENT state -> {detail}")
        if state in {ClientState.DISCONNECTED, ClientState.ERROR}:
            self._reconnect_at = time.time() + 5
            self._log_text("CLIENT reconnect scheduled in 5s")
        if state == ClientState.DISCONNECTED:
            self._remove_session(("client", id(self.client)))
        if state == ClientState.CONNECTED:
            self._pending_initial_request = True

    def _process_server_state(self, state: ServerState, info: Optional[str]) -> None:
        detail = state.value if info is None else f"{state.value} ({info})"
        self._log_text(f"SERVER state -> {detail}")
        if state == ServerState.CONNECTED:
            self.server_session_token = object()
            self.sessions[("server", self.server_session_token)] = {"config_sent": False}
        elif state in {ServerState.LISTENING, ServerState.STOPPED, ServerState.ERROR}:
            if self.server_session_token is not None:
                self._remove_session(("server", self.server_session_token))
                self.server_session_token = None
        if state == ServerState.ERROR:
            self._restart_server_at = time.time() + 5
            self._log_text("SERVER restart scheduled in 5s")

    # ------------------------------------------------------------------
    # Session helpers

    def _session_key(self, transport: Transport) -> Tuple[str, object]:
        if transport is self.client:
            return ("client", id(self.client))
        if transport is self.server:
            if self.server_session_token is None:
                self.server_session_token = object()
            return ("server", self.server_session_token)
        return ("transport", id(transport))

    def _get_session(self, transport: Transport) -> Dict[str, object]:
        key = self._session_key(transport)
        return self.sessions.setdefault(key, {"config_sent": False})

    def _remove_session(self, key: Tuple[str, object]) -> None:
        self.sessions.pop(key, None)

    # ------------------------------------------------------------------
    # Command helpers

    def _maybe_send_dcu_config(self, frame: Frame, transport: Transport, session: Dict[str, object]) -> None:
        if session.get("config_sent"):
            return
        payload = self._build_dcu_config_payload(frame.data)
        if payload is None:
            return
        dest = frame.sid
        if dest is None:
            return
        sid = self._resolve_sid(dest)
        try:
            transport.send_command(Command.DCU_CONFIGURE, payload, did=dest, sid=sid)
            session["config_sent"] = True
            session["suppress_ack_once"] = True
            session["dcu_info_data"] = payload
        except RuntimeError as exc:  # noqa: BLE001
            self._log_text(f"ERROR sending config: {exc}")

    def _auto_ack(self, frame: Frame, transport: Transport, session: Dict[str, object]) -> None:
        if session.get("suppress_ack_once"):
            session.pop("suppress_ack_once", None)
            return
        if frame.cmd in {Command.ACK, Command.NACK}:
            return
        dest = frame.sid
        if dest is None:
            return
        sid = self._resolve_sid(dest)
        try:
            transport.send_command(Command.ACK, b"", did=dest, sid=sid)
        except RuntimeError:
            pass

    def _update_rmu_table_cache(self, session: Dict[str, object], parsed: Dict[str, object]) -> None:
        rmu = parsed.get("rmu_id")
        if isinstance(rmu, dict):
            rcu = rmu.get("rcu")
            tcu = rmu.get("tcu")
            if isinstance(rcu, int) and isinstance(tcu, int):
                session.setdefault("rmu_readings", {})[(rcu, tcu)] = parsed

    def _resolve_sid(self, dest: int | None) -> int:
        if self.settings.get("sid_match", True) and dest is not None:
            return dest
        return self.settings.get("sid", 0)

    # ------------------------------------------------------------------
    # Logging helpers

    def _ensure_data_log_path(self) -> Path:
        today = datetime.now().strftime("%Y%m%d")
        if self.data_log_path is None or self.data_log_path.stem.split("_")[0] != today:
            self.data_log_path = self.base_path / f"{today}_data.txt"
        return self.data_log_path

    def _log_data(self, direction: str, frame_bytes: bytes) -> None:
        path = self._ensure_data_log_path()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hex_str = " ".join(f"{b:02X}" for b in frame_bytes)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp}] DEBUG - {direction}[{len(frame_bytes)}] {hex_str}\n")

    def _log_parsed_info(self, frame: Frame, parsed: Dict[str, object]) -> None:
        path = self._ensure_data_log_path()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ascii_char = chr(frame.cmd).upper() if 32 <= frame.cmd <= 126 else ""
        lines = [f"[{timestamp}] INFO  - CMD - {frame.cmd:02X} {ascii_char}".rstrip()]
        if frame.cmd == Command.DCU_INFO_RESPONSE:
            dcu_id = frame.sid if frame.sid is not None else "-"
            lines.append(f"[{timestamp}] INFO  - DCU ID     : {dcu_id}")
            lines.append(f"[{timestamp}] INFO  - ============================[{ascii_char.lower()}]")
            if parsed.get("timestamp"):
                lines.append(f"[{timestamp}] INFO  - TIME        : {parsed['timestamp']}")
            if parsed.get("firmware_version"):
                lines.append(f"[{timestamp}] INFO  - F/W VER     : {parsed['firmware_version']}")
            lines.append(f"[{timestamp}] INFO  - FEP IP      : {parsed.get('fep_ip')}")
            lines.append(f"[{timestamp}] INFO  - FEP PORT    : {parsed.get('fep_port')}")
            lines.append(f"[{timestamp}] INFO  - DCU IP      : {parsed.get('dcu_ip')}")
            lines.append(f"[{timestamp}] INFO  - DCU PORT    : {parsed.get('dcu_port')}")
            lines.append(f"[{timestamp}] INFO  - SEND PERIOD : {parsed.get('send_period_min')}")
            lines.append(f"[{timestamp}] INFO  - LOG PERIOD  : {parsed.get('log_period_min')}")
            lines.append(f"[{timestamp}] INFO  - RETRY COUNT : {parsed.get('retry_count')}")
            lines.append(f"[{timestamp}] INFO  - POWER STATE : {parsed.get('power_state')}")
        elif frame.cmd == Command.RMU_INFO_RESPONSE and parsed.get("items"):
            for item in parsed["items"]:
                rmu = item.get("rmu_id")
                rmu_label = rmu
                if isinstance(rmu, dict):
                    rcu = rmu.get("rcu")
                    tcu = rmu.get("tcu")
                    if isinstance(rcu, int) and isinstance(tcu, int):
                        rmu_label = (rcu << 8) | tcu
                lines.append(f"[{timestamp}] INFO  - ============================[{ascii_char.lower()}]")
                lines.append(f"[{timestamp}] INFO  - RMU ID      : {rmu_label}")
                if item.get("firmware_version"):
                    lines.append(f"[{timestamp}] INFO  - F/W VER     : {item['firmware_version']}")
                if item.get("measured_at"):
                    lines.append(f"[{timestamp}] INFO  - TIME        : {item['measured_at']}")
                lines.append(f"[{timestamp}] INFO  - NW INDEX    : {item.get('network_index')}")
                raw_type = item.get("meter_type_raw")
                m_type_val = f"{raw_type:02X}" if isinstance(raw_type, int) else item.get("meter_type")
                lines.append(f"[{timestamp}] INFO  - M TYPE      : {m_type_val}")
                if item.get("meter_protocol") is not None:
                    lines.append(f"[{timestamp}] INFO  - MP TYPE     : 0x{item.get('meter_protocol'):02X}")
                if item.get("meter_interface") is not None:
                    lines.append(f"[{timestamp}] INFO  - MI TYPE     : 0x{item.get('meter_interface'):02X}")
                if item.get("power_type") is not None:
                    lines.append(f"[{timestamp}] INFO  - P TYPE      : 0x{item.get('power_type'):02X}")
        elif frame.cmd in {
            Command.PERIODIC_READING_RESPONSE,
            Command.CURRENT_READING_RESPONSE,
            Command.SAVED_READING_RESPONSE,
        }:
            rmu = parsed.get("rmu_id")
            rmu_label = rmu
            if isinstance(rmu, dict):
                rcu = rmu.get("rcu")
                tcu = rmu.get("tcu")
                if isinstance(rcu, int) and isinstance(tcu, int):
                    rmu_label = (rcu << 8) | tcu
            lines.append(f"[{timestamp}] INFO  - DCU ID     : {frame.sid if frame.sid is not None else '-'}")
            lines.append(f"[{timestamp}] INFO  - ============================[{ascii_char.lower()}]")
            lines.append(f"[{timestamp}] INFO  - RMU ID      : {rmu_label}")
            if parsed.get("timestamp"):
                lines.append(f"[{timestamp}] INFO  - TIME        : {parsed['timestamp']}")
            dumps = parsed.get("dumps", [])
            for idx, dump in enumerate(dumps, start=1):
                mt_raw = dump.get("meter_type_raw")
                if isinstance(mt_raw, int):
                    lines.append(f"[{timestamp}] INFO  - M TYPE      : {mt_raw:02X}")
                value = self._format_meter_dump(dump)
                lines.append(f"[{timestamp}] INFO  - MDATA{idx:<2}      : {value}")
        if len(lines) == 1:
            return
        with path.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    def _format_meter_dump(self, dump: Dict[str, object]) -> str:
        interp = dump.get("interpreted")
        if isinstance(interp, dict) and "value" in interp:
            try:
                value = float(interp["value"])
                return f"{value:.3f}"
            except (TypeError, ValueError):
                pass
        raw = dump.get("raw_value")
        if isinstance(raw, str) and raw:
            return raw
        return "-"

    def _log_login_info(self, frame: Frame, parsed: Dict[str, object]) -> None:
        line = (
            f"{datetime.now():%Y-%m-%d %H:%M:%S},DCU ID={frame.sid if frame.sid is not None else '-'},"
            f"F/W={parsed.get('firmware_version')},IP={parsed.get('dcu_ip')},PORT={parsed.get('dcu_port')}\n"
        )
        with (self.base_path / "Login.txt").open("a", encoding="utf-8") as fh:
            fh.write(line)

    # ------------------------------------------------------------------
    def _build_dcu_config_payload(self, data: bytes) -> Optional[bytes]:
        if len(data) < 27:
            return None
        payload = bytearray()
        payload.extend(pack_datetime(datetime.now()))
        payload.extend(self._parse_ip(self.settings.get("fep_ip"), data[7:11]))
        fep_port = int(self.settings.get("fep_port", 9008))
        payload.extend(int(fep_port).to_bytes(4, "little", signed=False))
        payload.extend(self._parse_ip(self.settings.get("dcu_ip"), data[15:19]))
        dcu_port = int(self.settings.get("dcu_port", int.from_bytes(data[19:23], "little")))
        payload.extend(int(max(0, min(dcu_port, 0xFFFFFFFF))).to_bytes(4, "little", signed=False))
        send_period = int(self.settings.get("send_period", int.from_bytes(data[23:25], "little")))
        send_period = max(5, min(send_period, 24 * 60))
        payload.extend(int(send_period).to_bytes(2, "little", signed=False))
        payload.extend(data[25:27])
        retry = data[27] if len(data) >= 28 else 1
        payload.append(retry)
        return bytes(payload)

    def _parse_ip(self, text: Optional[str], fallback: bytes) -> bytes:
        if text:
            try:
                return ipaddress.IPv4Address(text.strip()).packed
            except (ValueError, AttributeError):
                pass
        return fallback[:4]

    def _handle_sent_frame(self, frame_bytes: bytes, transport: Transport) -> None:
        self.events.put(("sent", frame_bytes))

    def _maybe_reconnect(self) -> None:
        if self._reconnect_at is None:
            return
        if time.time() >= self._reconnect_at:
            self._reconnect_at = None
            self._connect_client()

    def _maybe_restart_server(self) -> None:
        if self._restart_server_at is None:
            return
        if time.time() < self._restart_server_at:
            return
        self._restart_server_at = None
        self._log_text("SERVER restarting")
        try:
            self.server.stop()
        finally:
            self.server.start()

    def _maybe_send_initial(self) -> None:
        if not self._pending_initial_request:
            return
        if self.client.state != ClientState.CONNECTED:
            return
        self._pending_initial_request = False
        did = int(self.settings.get("dcu_id", 0))
        sid = self._resolve_sid(did)
        try:
            self.client.send_command(Command.DCU_INFO_REQUEST, b"", did=did, sid=sid)
        except RuntimeError:
            self._reconnect_at = time.time() + 5

    def _handle_signal(self, sig: int, frame) -> None:  # noqa: ANN001, D401
        self.running = False

    def _load_settings(self) -> Dict[str, int | str | bool]:
        config = configparser.ConfigParser()
        config.read(self.settings_path, encoding="utf-8")
        sec = config["connection"] if config.has_section("connection") else {}
        settings: Dict[str, int | str | bool] = {}
        settings["host"] = sec.get("host", "127.0.0.1")
        settings["port"] = int(sec.get("port", "15000"), 0)
        settings["dcu_id"] = int(sec.get("did", "0"), 0)
        settings["sid"] = int(sec.get("sid", "0"), 0)
        settings["fep_ip"] = sec.get("fep_ip", "127.0.0.1")
        settings["fep_port"] = int(sec.get("fep_port", "9008"), 0)
        settings["dcu_ip"] = sec.get("dcu_ip", "")
        settings["dcu_port"] = int(sec.get("dcu_port", "10001"), 0)
        settings["send_period"] = int(sec.get("periodic_interval", "10"), 0)
        settings["auto_ack"] = sec.get("auto_ack", "True").lower() != "false"
        settings["sid_match"] = sec.get("sid_match", "True").lower() != "false"
        return settings

    def _log_text(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._ensure_data_log_path().open("a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp}] INFO  - {message}\n")

    def _ensure_config_exists(self) -> None:
        if self.settings_path.exists():
            return
        config = configparser.ConfigParser()
        config["connection"] = {
            "host": "127.0.0.1",
            "port": "15000",
            "did": "0x0000",
            "sid": "0x0000",
            "rcu": "0",
            "tcu": "0",
            "fep_ip": "127.0.0.1",
            "fep_port": "9008",
            "auto_ack": "True",
            "sid_match": "True",
            "dcu_ip": "",
            "dcu_port": "10001",
            "dcu_send": "10",
            "dcu_log": "0",
            "dcu_retry": "1",
            "rmu_mtype": "0x01",
            "rmu_wperiod": "0",
            "rmu_tperiod": "0",
            "rmu_tdelay": "0",
            "rmu_emtype": "0x00",
            "rmu_mptype": "0x01",
            "rmu_mi": "0x01",
            "rmu_power": "0x01",
            "periodic_interval": "10",
            "pulse_value": "0.0",
            "pulse_type": "수도(WM)",
        }
        with self.settings_path.open("w", encoding="utf-8") as fh:
            config.write(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DCU Service Mode")
    parser.add_argument(
        "--config",
        default="FepSever_init.ini",
        help="Path to FepSever_init.ini configuration file",
    )
    args = parser.parse_args(argv)
    settings_path = Path(args.config)
    service = ServiceMode(settings_path)
    service.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
