from __future__ import annotations

import configparser
import ipaddress
import json
import queue
import struct
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Dict, Tuple

from dcutools import (
    ClientState,
    Command,
    DcuTcpClient,
    DcuTcpServer,
    Frame,
    PacketParser,
    ServerState,
    Transport,
    build_rmu_id,
)
from dcutools.protocol import EOF, SOF, apply_dle, pack_datetime


class DcuApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DCU Reader")
        self.root.geometry("920x640")

        # UI variables
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="15000")
        self.did_var = tk.StringVar(value="0x0001")
        self.sid_var = tk.StringVar(value="0x0000")
        self.rcu_var = tk.StringVar(value="0")
        self.tcu_var = tk.StringVar(value="0")
        self.fep_ip_var = tk.StringVar(value="127.0.0.1")
        self.fep_port_var = tk.StringVar(value="9008")
        self.auto_ack_var = tk.BooleanVar(value=True)
        self.sid_match_var = tk.BooleanVar(value=True)
        self.dcu_ip_var = tk.StringVar(value="")
        self.dcu_port_var = tk.StringVar(value="")
        self.dcu_send_period_var = tk.StringVar(value="")
        self.dcu_log_period_var = tk.StringVar(value="")
        self.dcu_retry_var = tk.StringVar(value="")
        self.rmu_mtype_choices = [
            "전기(EM)",
            "수도(WM)",
            "온수(HM)",
            "가스(GM)",
            "열량(CM)",
        ]
        self.rmu_mtype_var = tk.StringVar(value=self.rmu_mtype_choices[0])
        self.protocol_type_choices = [
            "0_None",
            "1_Pulse",
            "2_DCPLC-A",
            "3_DCPLC-B",
            "4_DCPLC-C",
            "5_DCPLC-DM",
            "6_DCPLC-DS",
        ]
        self.rmu_protocol_var = tk.StringVar(value=self.protocol_type_choices[0])
        self.periodic_interval_var = tk.StringVar(value="10")
        self.pulse_value_var = tk.StringVar(value="0.0")
        self.rmu_meter_type_options = ["전체", "전기(EM)", "수도(WM)", "온수(HM)", "가스(GM)", "열량(CM)"]
        self.rmu_meter_type_var = tk.StringVar(value="전체")
        self.rmu_info_cache: Dict[Tuple[int, int], Dict[str, object]] = {}
        self.rmu_data_vars = {
            "meter_id": tk.StringVar(),
            "firmware": tk.StringVar(),
            "em": tk.StringVar(),
            "wm": tk.StringVar(),
            "hm": tk.StringVar(),
            "gm": tk.StringVar(),
            "cm": tk.StringVar(),
        }

        self.settings_path = Path("FepSever_init.ini")
        self.base_path = self.settings_path.resolve().parent
        self.data_log_path: Path | None = None

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
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.sessions: Dict[Tuple[str, object], Dict[str, object]] = {}
        self.server_session_token: object | None = None
        self.terminal_output: scrolledtext.ScrolledText | None = None
        self.terminal_mode: tk.StringVar | None = None
        self.terminal_command_var: tk.StringVar | None = None
        self.terminal_data_var: tk.StringVar | None = None

        self._load_settings()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_events)

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        connection_frame = ttk.LabelFrame(main, text="Connection")
        connection_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(connection_frame, text="DCU").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=4)
        ttk.Entry(connection_frame, textvariable=self.host_var, width=18).grid(row=0, column=1, pady=4, sticky=tk.W)
        ttk.Label(connection_frame, text="Port").grid(row=0, column=2, sticky=tk.W, padx=(12, 4))
        ttk.Entry(connection_frame, textvariable=self.port_var, width=8).grid(row=0, column=3, pady=4, sticky=tk.W)
        ttk.Label(connection_frame, text="DCU ID").grid(row=0, column=4, sticky=tk.W, padx=(12, 4))
        ttk.Entry(connection_frame, textvariable=self.did_var, width=10).grid(row=0, column=5, pady=4, sticky=tk.W)
        # SID 입력 필드는 숨김 (SID=DCU 모드 사용)

        ttk.Label(connection_frame, text="RCU ID").grid(row=1, column=0, sticky=tk.W, padx=(8, 4))
        ttk.Entry(connection_frame, textvariable=self.rcu_var, width=8).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(connection_frame, text="TCU ID").grid(row=1, column=2, sticky=tk.W, padx=(12, 4))
        tcu_entry = ttk.Entry(connection_frame, textvariable=self.tcu_var, width=8)
        tcu_entry.grid(row=1, column=3, sticky=tk.W)
        ttk.Label(connection_frame, text="FEP IP").grid(row=1, column=4, sticky=tk.W, padx=(12, 4))
        ttk.Entry(connection_frame, textvariable=self.fep_ip_var, width=16).grid(row=1, column=5, sticky=tk.W)
        ttk.Label(connection_frame, text="FEP Port").grid(row=1, column=6, sticky=tk.W, padx=(12, 4))
        ttk.Entry(connection_frame, textvariable=self.fep_port_var, width=8).grid(row=1, column=7, sticky=tk.W)

        ttk.Checkbutton(connection_frame, text="SID=DCU", variable=self.sid_match_var).grid(row=2, column=0, sticky=tk.W, padx=(8, 4))

        tcu_entry.bind("<Return>", lambda _e: self._send_tcu_status(silent=True))
        tcu_entry.bind("<FocusOut>", lambda _e: self._send_tcu_status(silent=True))

        btn_connect = ttk.Button(connection_frame, text="Connect", command=self._connect)
        btn_connect.grid(row=2, column=6, padx=8, pady=(4, 8))
        btn_disconnect = ttk.Button(connection_frame, text="Disconnect", command=self._disconnect)
        btn_disconnect.grid(row=2, column=7, padx=8, pady=(4, 8))

        for child in connection_frame.winfo_children():
            child.grid_configure(pady=4)

        commands_frame = ttk.LabelFrame(main, text="Commands")
        commands_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Button(commands_frame, text="DCU Info", command=lambda: self._send_simple(Command.DCU_INFO_REQUEST)).grid(row=0, column=0, padx=6, pady=4)
        ttk.Button(commands_frame, text="RMU List", command=lambda: self._send_simple(Command.RMU_LIST_REQUEST)).grid(row=0, column=1, padx=6, pady=4)
        ttk.Button(commands_frame, text="RMU Info", command=self._send_rmu_info).grid(row=0, column=2, padx=6, pady=4)
        ttk.Button(commands_frame, text="Current Reading", command=lambda: self._send_rmu_target(Command.CURRENT_READING_REQUEST)).grid(row=0, column=3, padx=6, pady=4)
        ttk.Button(commands_frame, text="Periodic Reading", command=lambda: self._send_rmu_target(Command.PERIODIC_READING_REQUEST)).grid(row=0, column=4, padx=6, pady=4)
        ttk.Button(commands_frame, text="Saved Reading", command=lambda: self._send_rmu_target(Command.SAVED_READING_REQUEST)).grid(row=0, column=5, padx=6, pady=4)
        ttk.Checkbutton(commands_frame, text="Auto ACK", variable=self.auto_ack_var).grid(row=0, column=6, padx=12, pady=4)
        ttk.Button(commands_frame, text="TCU Status", command=lambda: self._send_tcu_status()).grid(row=0, column=7, padx=6, pady=4)

        config_frame = ttk.Frame(main)
        config_frame.pack(fill=tk.X, pady=(0, 8))

        dcu_cfg = ttk.LabelFrame(config_frame, text="DCU Config")
        dcu_cfg.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 8))

        ttk.Label(dcu_cfg, text="DCU IP").grid(row=0, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.dcu_ip_var, width=16).grid(row=0, column=1, pady=2, sticky=tk.W)
        ttk.Label(dcu_cfg, text="DCU Port").grid(row=0, column=2, sticky=tk.W, padx=(12, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.dcu_port_var, width=10).grid(row=0, column=3, pady=2, sticky=tk.W)

        ttk.Label(dcu_cfg, text="Send Period (min)").grid(row=1, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.dcu_send_period_var, width=10).grid(row=1, column=1, pady=2, sticky=tk.W)
        ttk.Label(dcu_cfg, text="Log Period (min)").grid(row=1, column=2, sticky=tk.W, padx=(12, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.dcu_log_period_var, width=10).grid(row=1, column=3, pady=2, sticky=tk.W)

        ttk.Label(dcu_cfg, text="Retry Count").grid(row=2, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.dcu_retry_var, width=10).grid(row=2, column=1, pady=2, sticky=tk.W)
        ttk.Label(dcu_cfg, text="Periodic (min)").grid(row=2, column=2, sticky=tk.W, padx=(12, 4), pady=2)
        ttk.Entry(dcu_cfg, textvariable=self.periodic_interval_var, width=10).grid(row=2, column=3, pady=2, sticky=tk.W)
        ttk.Button(dcu_cfg, text="Send", command=self._send_dcu_config).grid(row=3, column=3, padx=4, pady=4, sticky=tk.E)

        for col in range(4):
            dcu_cfg.grid_columnconfigure(col, weight=1)

        rmu_cfg = ttk.LabelFrame(config_frame, text="RMU Config")
        rmu_cfg.grid(row=0, column=1, sticky=tk.NSEW)

        ttk.Label(rmu_cfg, text="RCU ID").grid(row=0, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Entry(rmu_cfg, textvariable=self.rcu_var, width=6).grid(row=0, column=1, pady=2, sticky=tk.W)
        ttk.Label(rmu_cfg, text="RMU ID").grid(row=0, column=2, sticky=tk.W, padx=(12, 4), pady=2)
        ttk.Entry(rmu_cfg, textvariable=self.tcu_var, width=6).grid(row=0, column=3, pady=2, sticky=tk.W)

        ttk.Label(rmu_cfg, text="MType").grid(row=1, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Combobox(
            rmu_cfg,
            textvariable=self.rmu_mtype_var,
            values=self.rmu_mtype_choices,
            state="readonly",
            width=14,
        ).grid(row=1, column=1, pady=2, sticky=tk.W)
        ttk.Label(rmu_cfg, text="ProtocolType").grid(row=1, column=2, sticky=tk.W, padx=(12, 4), pady=2)
        ttk.Combobox(
            rmu_cfg,
            textvariable=self.rmu_protocol_var,
            values=self.protocol_type_choices,
            state="readonly",
            width=14,
        ).grid(row=1, column=3, pady=2, sticky=tk.W)

        ttk.Label(rmu_cfg, text="Pulse Init").grid(row=2, column=0, sticky=tk.W, padx=(6, 4), pady=2)
        ttk.Entry(rmu_cfg, textvariable=self.pulse_value_var, width=14).grid(row=2, column=1, pady=2, sticky=tk.W)
        ttk.Button(rmu_cfg, text="Set", command=self._send_pulse_init).grid(row=2, column=3, padx=4, pady=2, sticky=tk.E)

        ttk.Button(rmu_cfg, text="Read", command=self._send_rmu_info).grid(row=3, column=2, padx=4, pady=4, sticky=tk.E)
        ttk.Button(rmu_cfg, text="Send", command=self._send_rmu_config).grid(row=3, column=3, padx=4, pady=4, sticky=tk.E)

        for col in range(4):
            rmu_cfg.grid_columnconfigure(col, weight=1)

        data_frame = ttk.LabelFrame(config_frame, text="RMU Data")
        data_frame.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=(8, 0))
        headers = [
            "MeterID",
            "F/W Version",
            "전기(EM)",
            "수도(WM)",
            "온수(HM)",
            "가스(GM)",
            "열량(CM)",
            "MeterType",
        ]
        for idx, title in enumerate(headers):
            ttk.Label(data_frame, text=title).grid(row=0, column=idx, padx=4, pady=(2, 2))
        keys = ["meter_id", "firmware", "em", "wm", "hm", "gm", "cm", "meter_type"]
        for idx, key in enumerate(keys):
            if key == "meter_type":
                ttk.Combobox(
                    data_frame,
                    textvariable=self.rmu_meter_type_var,
                    values=self.rmu_meter_type_options,
                    width=12,
                    state="readonly",
                ).grid(row=1, column=idx, padx=4, pady=(0, 2))
            else:
                entry = ttk.Entry(data_frame, textvariable=self.rmu_data_vars[key], width=14, state="readonly")
                entry.grid(row=1, column=idx, padx=4, pady=(0, 2))

        ttk.Button(data_frame, text="가져오기", command=lambda: self._send_rmu_target(Command.CURRENT_READING_REQUEST)).grid(row=1, column=8, padx=(8, 0))

        status_frame = ttk.Frame(main)
        status_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="disconnected")
        ttk.Label(status_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT, padx=(4, 0))

        body = ttk.Panedwindow(main, orient=tk.VERTICAL)
        body.pack(fill=tk.BOTH, expand=True)

        top_pane = ttk.Panedwindow(body, orient=tk.HORIZONTAL)
        log_frame = ttk.Labelframe(top_pane, text="Log")
        self.log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=16)
        self.log_widget.pack(fill=tk.BOTH, expand=True)
        top_pane.add(log_frame, weight=1)

        detail_frame = ttk.Labelframe(top_pane, text="Last Packet")
        self.detail_widget = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD)
        self.detail_widget.pack(fill=tk.BOTH, expand=True)
        top_pane.add(detail_frame, weight=1)
        body.add(top_pane, weight=3)

        terminal_frame = ttk.Labelframe(body, text="터미널")
        terminal_frame.columnconfigure(0, weight=1)
        terminal_frame.rowconfigure(0, weight=1)

        self.terminal_output = scrolledtext.ScrolledText(terminal_frame, wrap=tk.WORD, height=10, font=("Consolas", 10))
        self.terminal_output.configure(state=tk.DISABLED)
        self.terminal_output.grid(row=0, column=0, sticky="nsew")

        terminal_controls = ttk.Frame(terminal_frame)
        terminal_controls.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        terminal_controls.columnconfigure(5, weight=1)

        self.terminal_mode = tk.StringVar(value="command")
        ttk.Radiobutton(terminal_controls, text="명령", variable=self.terminal_mode, value="command").grid(row=0, column=0, padx=(0, 8))
        ttk.Radiobutton(terminal_controls, text="프레임", variable=self.terminal_mode, value="frame").grid(row=0, column=1, padx=(0, 12))

        ttk.Label(terminal_controls, text="CMD").grid(row=0, column=2, sticky=tk.E)
        self.terminal_command_var = tk.StringVar(value="G")
        ttk.Entry(terminal_controls, textvariable=self.terminal_command_var, width=10).grid(row=0, column=3, padx=(4, 12))

        ttk.Label(terminal_controls, text="HEX 데이터").grid(row=0, column=4, sticky=tk.E)
        self.terminal_data_var = tk.StringVar()
        ttk.Entry(terminal_controls, textvariable=self.terminal_data_var, width=40).grid(row=0, column=5, padx=(4, 12), sticky=tk.EW)

        ttk.Button(terminal_controls, text="전송", command=self._send_custom).grid(row=0, column=6, padx=(0, 8))
        ttk.Button(terminal_controls, text="지우기", command=self._clear_terminal).grid(row=0, column=7)

        body.add(terminal_frame, weight=2)

        self._log("Application ready")
        self._terminal_log("INFO", "터미널 준비 완료")

    def _connect(self) -> None:
        try:
            host = self.host_var.get().strip()
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be an integer")
            return

        try:
            fep_port = int(self.fep_port_var.get())
        except ValueError:
            messagebox.showerror("Invalid FEP port", "FEP port must be an integer")
            return

        self._stop_server()
        self._start_server(fep_port)
        self.client.connect(host, port)
        self._log(f"Connecting to {host}:{port} ...")

    def _disconnect(self) -> None:
        self.client.disconnect()
        self._stop_server()
        self._log("Disconnected")

    def _send_simple(self, command: Command) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))
            return
        try:
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
        except ValueError as exc:
            messagebox.showerror("Invalid addressing", str(exc))
            return
        try:
            self._send_command(transport, command, b"", did=did, sid=sid)
            self._record_tx(command, b"", did, sid)
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _send_rmu_info(self) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))
            return
        try:
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            rcu, tcu = self._get_rmu_ids()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        data = build_rmu_id(rcu, tcu)
        try:
            self._send_command(transport, Command.RMU_INFO_REQUEST, data, did=did, sid=sid)
            self._record_tx(Command.RMU_INFO_REQUEST, data, did, sid, extra=f"RCU={rcu} TCU={tcu}")
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _send_rmu_target(self, command: Command) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))
            return
        try:
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            rcu, tcu = self._get_rmu_ids()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        data = build_rmu_id(rcu, tcu)
        try:
            self._send_command(transport, command, data, did=did, sid=sid)
            self._record_tx(command, data, did, sid, extra=f"RCU={rcu} TCU={tcu}")
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _send_dcu_config(self) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("No connection", str(exc))
            return

        session = self._get_session(transport)
        base = session.get("dcu_info_data")
        if not isinstance(base, bytes) or len(base) < 27:
            base = b"\x00" * 27

        payload = bytearray()
        payload.extend(pack_datetime(datetime.now()))
        payload.extend(self._parse_ip_field(self.fep_ip_var.get(), base[7:11]))

        fep_port = self._get_fep_port_value()
        payload.extend(fep_port.to_bytes(4, "little", signed=False))

        payload.extend(self._parse_ip_field(self.dcu_ip_var.get(), base[15:19]))
        dcu_port = self._parse_int_field(self.dcu_port_var.get(), int.from_bytes(base[19:23], "little"))
        dcu_port = max(0, min(dcu_port, 0xFFFFFFFF))
        payload.extend(dcu_port.to_bytes(4, "little", signed=False))

        send_default = int.from_bytes(base[23:25], "little")
        send_period = self._parse_int_field(self.periodic_interval_var.get(), send_default)
        self.dcu_send_period_var.set(str(send_period))
        self.periodic_interval_var.set(str(send_period))
        log_period = self._parse_int_field(self.dcu_log_period_var.get(), int.from_bytes(base[25:27], "little"))
        send_period = max(0, min(send_period, 0xFFFF))
        log_period = max(0, min(log_period, 0xFFFF))
        payload.extend(send_period.to_bytes(2, "little", signed=False))
        payload.extend(log_period.to_bytes(2, "little", signed=False))

        retry_default = base[27] if len(base) >= 28 else 1
        retry = self._parse_int_field(self.dcu_retry_var.get(), retry_default) & 0xFF
        payload.append(retry)

        if len(payload) != 27:
            messagebox.showerror("Invalid payload", f"Unexpected config length {len(payload)}")
            return

        try:
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            self._send_command(transport, Command.DCU_CONFIGURE, bytes(payload), did=did, sid=sid)
            self._record_tx(Command.DCU_CONFIGURE, bytes(payload), did, sid, extra="manual-config")
            session["dcu_info_data"] = bytes(payload)
            session["config_sent"] = True
            session["suppress_ack_once"] = True
            self._save_settings()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _send_rmu_config(self) -> None:
        try:
            transport = self._get_active_transport()
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            rcu, tcu = self._get_rmu_ids()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        mtype_code = self._meter_type_label_to_code(self.rmu_mtype_var.get())
        protocol_code = self._protocol_label_to_code(self.rmu_protocol_var.get())

        payload = bytearray()
        payload.extend(build_rmu_id(rcu, tcu))
        payload.append(mtype_code & 0xFF)
        payload.append(0x00)  # write period (hours)
        payload.append(0x00)  # tx period (hours)
        payload.extend((0).to_bytes(2, "big", signed=False))  # tx delay (seconds)
        payload.append(0x00)  # energy meter type
        payload.append(protocol_code & 0xFF)
        payload.append(0x00)  # meter interface
        payload.append(0x00)  # power type

        try:
            self._send_command(transport, Command.RMU_CONFIGURE, bytes(payload), did=did, sid=sid)
            self._record_tx(Command.RMU_CONFIGURE, bytes(payload), did, sid, extra=f"RCU={rcu} TCU={tcu}")
            self._save_settings()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _send_tcu_status(self, *, silent: bool = False) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            if not silent:
                messagebox.showwarning("Not connected", str(exc))
            return
        try:
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            rcu, tcu = self._get_rmu_ids()
        except ValueError as exc:
            if not silent:
                messagebox.showerror("Invalid input", str(exc))
            return
        payload = build_rmu_id(rcu, tcu)
        try:
            self._send_command(transport, Command.CURRENT_READING_REQUEST, payload, did=did, sid=sid)
            self._record_tx(Command.CURRENT_READING_REQUEST, payload, did, sid, extra=f"RCU={rcu} TCU={tcu}")
        except RuntimeError as exc:
            if not silent:
                messagebox.showwarning("Not connected", str(exc))

    def _send_pulse_init(self) -> None:
        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))
            return
        try:
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            rcu, tcu = self._get_rmu_ids()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        try:
            value = float(self.pulse_value_var.get() or "0")
        except ValueError:
            messagebox.showerror("Invalid value", "Pulse 초기값은 숫자여야 합니다")
            return

        meter_type = self._pulse_meter_type_value()
        payload = bytearray()
        payload.extend(build_rmu_id(rcu, tcu))
        payload.append(0x01)  # CNT
        payload.append(meter_type)
        payload.extend(struct.pack('<f', value))

        try:
            self._send_command(transport, Command.RMU_PULSE_INIT, bytes(payload), did=did, sid=sid)
            self._record_tx(Command.RMU_PULSE_INIT, bytes(payload), did, sid, extra=f"RCU={rcu} TCU={tcu}")
            self._save_settings()
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _get_addressing(self) -> tuple[int, int]:
        return self._parse_int(self.did_var.get()), self._parse_int(self.sid_var.get())

    def _get_rmu_ids(self) -> tuple[int, int]:
        return self._parse_int(self.rcu_var.get()), self._parse_int(self.tcu_var.get())

    def _parse_int(self, value: str) -> int:
        value = value.strip()
        if not value:
            raise ValueError("value is required")
        return int(value, 0)

    def _get_active_transport(self) -> Transport:
        if self.server_session_token is not None and self.server.state == ServerState.CONNECTED:
            return self.server
        if self.client.state == ClientState.CONNECTED:
            return self.client
        raise RuntimeError("No active DCU connection")

    def _send_command(self, transport: Transport, cmd: Command, data: bytes, *, did: int, sid: int) -> None:
        transport.send_command(cmd, data, did=did, sid=sid)

    def _resolve_did(self, session: Dict[str, object]) -> int:
        dest = session.get("dcu_id")
        if isinstance(dest, int) and dest:
            return dest
        try:
            did, _ = self._get_addressing()
            return did
        except ValueError:
            return 0

    def _get_sid_value_raw(self) -> int:
        try:
            return self._parse_int(self.sid_var.get())
        except ValueError:
            return 0

    def _resolve_sid(self, dest: int | None) -> int:
        if self.sid_match_var.get() and dest is not None:
            return dest
        return self._get_sid_value_raw()

    def _handle_frame(self, frame: Frame, transport: Transport) -> None:
        self.events.put(("frame", frame, transport))

    def _handle_sent_frame(self, frame_bytes: bytes, transport: Transport) -> None:
        self.events.put(("sent", frame_bytes, transport))

    def _handle_client_state(self, state: ClientState, info: str | None) -> None:
        self.events.put(("client_state", state, info))

    def _handle_server_state(self, state: ServerState, info: str | None) -> None:
        self.events.put(("server_state", state, info))

    def _process_events(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            kind = event[0]
            if kind == "frame":
                self._process_frame(event[1], event[2])
            elif kind == "client_state":
                self._process_client_state(event[1], event[2] if len(event) > 2 else None)
            elif kind == "server_state":
                self._process_server_state(event[1], event[2] if len(event) > 2 else None)
            elif kind == "sent":
                self._process_sent_frame(event[1], event[2])
        self.root.after(100, self._process_events)

    def _process_frame(self, frame: Frame, transport: Transport) -> None:
        frame_bytes = bytes([SOF]) + apply_dle(frame.raw) + bytes([EOF])
        self._log_data("RECV", frame_bytes)

        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            command_name = Command(frame.cmd).name
        except ValueError:
            command_name = f"0x{frame.cmd:02X}"

        self._log(f"[{timestamp}] RX cmd={command_name} data={frame.data.hex()}")
        self._terminal_log(
            "RX",
            f"{command_name} DID=0x{frame.did:04X} SID=0x{frame.sid:04X} DATA={frame.data.hex()}",
        )
        try:
            parsed = self.packet_parser.parse(frame)
        except Exception as exc:
            self._set_detail_text(json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2))
            return
        self._set_detail_text(json.dumps(parsed, ensure_ascii=False, indent=2, default=str))
        self._log_parsed_info(frame, parsed)

        session = self._get_session(transport)
        if frame.sid:
            session["dcu_id"] = frame.sid
        session["fep_id"] = frame.did
        if frame.cmd == Command.DCU_INFO_RESPONSE:
            session["dcu_info_data"] = frame.data
            self._update_dcu_fields(parsed)
            self._log_login_info(frame, parsed)
        if frame.cmd == Command.RMU_INFO_RESPONSE and parsed.get("items"):
            for item in parsed["items"]:
                rmu = item.get("rmu_id", {})
                if isinstance(rmu, dict):
                    rcu = rmu.get("rcu")
                    tcu = rmu.get("tcu")
                    if isinstance(rcu, int) and isinstance(tcu, int):
                        self.rmu_info_cache[(rcu, tcu)] = item
            self._update_rmu_fields(parsed["items"][0])
        if frame.cmd in {Command.PERIODIC_READING_RESPONSE, Command.CURRENT_READING_RESPONSE, Command.SAVED_READING_RESPONSE}:
            self._update_rmu_table_data(parsed)
        self._maybe_send_dcu_config(frame, transport, session)

        if self.auto_ack_var.get():
            self._auto_ack(frame, transport, session)

    def _process_sent_frame(self, frame_bytes: bytes, transport: Transport) -> None:
        self._log_data("SEND", frame_bytes)

    def _process_client_state(self, state: ClientState, info: str | None) -> None:
        text = state.value if not info else f"{state.value} ({info})"
        self.status_var.set(text)
        self._log(f"Client state -> {text}")
        self._terminal_log("CLIENT", text)
        if state in {ClientState.DISCONNECTED, ClientState.ERROR}:
            self._remove_session(("client", id(self.client)))

    def _process_server_state(self, state: ServerState, info: str | None) -> None:
        message = state.value if not info else f"{state.value} ({info})"
        if state == ServerState.CONNECTED:
            self.server_session_token = object()
            self.sessions[("server", self.server_session_token)] = {"config_sent": False}
        elif state in {ServerState.LISTENING, ServerState.STOPPED, ServerState.ERROR}:
            if self.server_session_token is not None:
                self._remove_session(("server", self.server_session_token))
                self.server_session_token = None
        self._log(f"Server state -> {message}")
        self._terminal_log("SERVER", message)

    def _log(self, message: str) -> None:
        self.log_widget.insert(tk.END, message + "\n")
        self.log_widget.see(tk.END)

    def _set_detail_text(self, text: str) -> None:
        self.detail_widget.delete("1.0", tk.END)
        self.detail_widget.insert(tk.END, text)
        self.detail_widget.see("1.0")

    def _terminal_log(self, prefix: str, message: str) -> None:
        if not self.terminal_output:
            return
        self.terminal_output.configure(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"{prefix}> {message}\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.configure(state=tk.DISABLED)

    def _clear_terminal(self) -> None:
        if not self.terminal_output:
            return
        self.terminal_output.configure(state=tk.NORMAL)
        self.terminal_output.delete("1.0", tk.END)
        self.terminal_output.configure(state=tk.DISABLED)

    def _record_tx(self, cmd: int | Command, data: bytes, did: int, sid: int, *, extra: str | None = None) -> None:
        cmd_value = int(cmd)
        name = self._command_name(cmd_value)
        payload = data.hex() or "-"
        message = f"TX {name} DID=0x{did:04X} SID=0x{sid:04X} DATA={payload}"
        if extra:
            message += f" ({extra})"
        self._log(message)
        self._terminal_log("TX", message)

    def _command_name(self, cmd: int) -> str:
        try:
            return Command(cmd).name
        except ValueError:
            if 32 <= cmd <= 126:
                return f"'{chr(cmd)}'"
            return f"0x{cmd:02X}"

    def _send_custom(self) -> None:
        if not self.terminal_mode or not self.terminal_data_var:
            return

        mode = self.terminal_mode.get()
        data_text = self.terminal_data_var.get()

        try:
            transport = self._get_active_transport()
        except RuntimeError as exc:
            messagebox.showwarning("No connection", str(exc))
            return

        try:
            if mode == "frame":
                frame_bytes = self._parse_hex_bytes(data_text)
                if not frame_bytes:
                    raise ValueError("프레임 데이터를 입력하세요")
                transport.send_frame(frame_bytes)
                message = f"TX raw frame len={len(frame_bytes)} DATA={frame_bytes.hex()}"
                self._log(message)
                self._terminal_log("TX", message)
                return

            if not self.terminal_command_var:
                raise ValueError("CMD 입력란을 찾을 수 없습니다")
            cmd_code = self._parse_command_code(self.terminal_command_var.get())
            payload = self._parse_hex_bytes(data_text)
            session = self._get_session(transport)
            did = self._resolve_did(session)
            sid = self._resolve_sid(did)
            self._send_command(transport, cmd_code, payload, did=did, sid=sid)
            self._record_tx(cmd_code, payload, did, sid)
        except ValueError as exc:
            messagebox.showerror("입력 오류", str(exc))
        except RuntimeError as exc:
            messagebox.showwarning("Not connected", str(exc))

    def _parse_command_code(self, value: str) -> int:
        text = (value or "").strip()
        if not text:
            raise ValueError("CMD 값을 입력하세요")
        if len(text) == 1:
            return ord(text)
        upper = text.upper()
        if upper in Command.__members__:
            return Command[upper].value
        try:
            return int(text, 0)
        except ValueError as exc:
            raise ValueError("CMD 는 문자, 명령 이름 또는 숫자(예: 0x47)로 입력하세요") from exc

    def _parse_hex_bytes(self, text: str) -> bytes:
        cleaned = (text or "").strip()
        if not cleaned:
            return b""

        tokens = cleaned.replace(",", " ").split()
        if len(tokens) > 1:
            try:
                return bytes(int(token, 16) for token in tokens)
            except ValueError as exc:
                raise ValueError("잘못된 HEX 데이터입니다") from exc

        token = tokens[0]
        token = token.replace("0x", "")
        if len(token) % 2 != 0:
            raise ValueError("HEX 데이터 길이는 짝수여야 합니다")
        try:
            return bytes(int(token[i:i + 2], 16) for i in range(0, len(token), 2))
        except ValueError as exc:
            raise ValueError("잘못된 HEX 데이터입니다") from exc

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
        session = self.sessions.setdefault(key, {"config_sent": False})
        return session

    def _remove_session(self, key: Tuple[str, object]) -> None:
        self.sessions.pop(key, None)

    def _maybe_send_dcu_config(self, frame: Frame, transport: Transport, session: Dict[str, object]) -> None:
        if frame.cmd != Command.DCU_INFO_RESPONSE:
            return
        if session.get("config_sent"):
            return
        try:
            payload = self._build_dcu_config_payload(frame.data)
        except ValueError as exc:
            self._terminal_log("WARN", f"Config skipped: {exc}")
            return

        dest = frame.sid
        if dest is None:
            return

        sid = self._resolve_sid(dest)
        try:
            transport.send_command(Command.DCU_CONFIGURE, payload, did=dest, sid=sid)
        except RuntimeError as exc:
            self._terminal_log("ERROR", f"Config send failed: {exc}")
            return

        self._record_tx(Command.DCU_CONFIGURE, payload, dest, sid, extra="auto-config")
        session["config_sent"] = True
        session["config_sent_at"] = datetime.now()
        session["suppress_ack_once"] = True

    def _build_dcu_config_payload(self, data: bytes) -> bytes:
        if len(data) < 27:
            raise ValueError("DCU info payload too short")

        payload = bytearray()
        payload.extend(pack_datetime(datetime.now()))

        payload.extend(self._parse_ip_field(self.fep_ip_var.get(), data[7:11]))

        fep_port = self._get_fep_port_value()
        payload.extend(fep_port.to_bytes(4, "little", signed=False))

        payload.extend(self._parse_ip_field(self.dcu_ip_var.get(), data[15:19]))
        dcu_port = self._parse_int_field(self.dcu_port_var.get(), int.from_bytes(data[19:23], "little"))
        dcu_port = max(0, min(dcu_port, 0xFFFFFFFF))
        payload.extend(dcu_port.to_bytes(4, "little", signed=False))

        base_send = int.from_bytes(data[23:25], "little")
        send_period = self._parse_int_field(self.periodic_interval_var.get(), base_send)
        self.dcu_send_period_var.set(str(send_period))
        self.periodic_interval_var.set(str(send_period))
        log_period = self._parse_int_field(self.dcu_log_period_var.get(), int.from_bytes(data[25:27], "little"))
        send_period = max(0, min(send_period, 0xFFFF))
        log_period = max(0, min(log_period, 0xFFFF))
        payload.extend(send_period.to_bytes(2, "little", signed=False))
        payload.extend(log_period.to_bytes(2, "little", signed=False))

        retry_default = data[27] if len(data) >= 28 else 1
        retry = self._parse_int_field(self.dcu_retry_var.get(), retry_default) & 0xFF
        payload.append(retry)

        if len(payload) != 27:
            raise ValueError(f"Unexpected config payload length {len(payload)} (expected 27)")

        return bytes(payload)

    def _parse_ip_field(self, value: str, fallback: bytes) -> bytes:
        text = (value or "").strip()
        if text:
            try:
                return ipaddress.IPv4Address(text).packed
            except ipaddress.AddressValueError:
                self._terminal_log("WARN", f"Invalid IP '{text}', using fallback")
        return fallback[:4] if len(fallback) >= 4 else b"\x00\x00\x00\x00"

    def _parse_int_field(self, text: str, default: int) -> int:
        text = (text or "").strip()
        if not text:
            return default
        try:
            return int(text, 0)
        except ValueError:
            self._terminal_log("WARN", f"Invalid integer '{text}', using {default}")
            return default

    def _parse_byte_field(self, text: str, default: int) -> int:
        return self._parse_int_field(text, default) & 0xFF

    def _get_fep_port_value(self) -> int:
        try:
            port = int(self.fep_port_var.get())
        except ValueError:
            self._terminal_log("WARN", "Invalid FEP port value, using 0")
            return 0
        return max(0, min(port, 0xFFFFFFFF))

    def _update_dcu_fields(self, parsed: Dict[str, object]) -> None:
        if parsed.get("dcu_ip"):
            self.dcu_ip_var.set(str(parsed.get("dcu_ip")))
        if parsed.get("dcu_port") is not None:
            self.dcu_port_var.set(str(parsed.get("dcu_port")))
        if parsed.get("send_period_min") is not None:
            self.dcu_send_period_var.set(str(parsed.get("send_period_min")))
            self.periodic_interval_var.set(str(parsed.get("send_period_min")))
        if parsed.get("log_period_min") is not None:
            self.dcu_log_period_var.set(str(parsed.get("log_period_min")))
        if parsed.get("retry_count") is not None:
            self.dcu_retry_var.set(str(parsed.get("retry_count")))

    def _update_rmu_fields(self, item: Dict[str, object]) -> None:
        raw = item.get("meter_type_raw")
        if isinstance(raw, int):
            self.rmu_mtype_var.set(self._meter_type_code_to_label(raw))
        protocol = item.get("meter_protocol")
        if isinstance(protocol, int):
            self.rmu_protocol_var.set(self._protocol_code_to_label(protocol))
        if item.get("write_period_h") is not None:
            self.periodic_interval_var.set(str(item.get("write_period_h")))

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
            lines.append(f"[{timestamp}] INFO  - ============================[{chr(frame.cmd).lower()}]")
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
                rmu = item.get("rmu_id", {})
                rmu_label = rmu
                if isinstance(rmu, dict):
                    rcu = rmu.get("rcu")
                    tcu = rmu.get("tcu")
                    if isinstance(rcu, int) and isinstance(tcu, int):
                        rmu_label = (rcu << 8) | tcu
                lines.append(f"[{timestamp}] INFO  - ============================[{chr(frame.cmd).lower()}]")
                lines.append(f"[{timestamp}] INFO  - RMU ID      : {rmu_label}")
                if item.get("firmware_version"):
                    lines.append(f"[{timestamp}] INFO  - F/W VER     : {item['firmware_version']}")
                if item.get("measured_at"):
                    lines.append(f"[{timestamp}] INFO  - TIME        : {item['measured_at']}")
                lines.append(f"[{timestamp}] INFO  - NW INDEX    : {item.get('network_index')}")
                raw_type = item.get("meter_type_raw")
                if isinstance(raw_type, int):
                    m_type_val = f"{raw_type:02X}"
                else:
                    m_type = item.get("meter_type")
                    m_type_val = ",".join(m_type) if isinstance(m_type, list) else str(m_type)
                lines.append(f"[{timestamp}] INFO  - M TYPE      : {m_type_val}")
                if item.get("meter_protocol") is not None:
                    lines.append(f"[{timestamp}] INFO  - MP TYPE     : 0x{item.get('meter_protocol'):02X}")
                if item.get("meter_interface") is not None:
                    lines.append(f"[{timestamp}] INFO  - MI TYPE     : 0x{item.get('meter_interface'):02X}")
                if item.get("power_type") is not None:
                    lines.append(f"[{timestamp}] INFO  - P TYPE      : 0x{item.get('power_type'):02X}")
        elif frame.cmd in {Command.PERIODIC_READING_RESPONSE, Command.CURRENT_READING_RESPONSE, Command.SAVED_READING_RESPONSE}:
            rmu = parsed.get("rmu_id", {})
            rmu_label = rmu
            if isinstance(rmu, dict):
                rcu = rmu.get("rcu")
                tcu = rmu.get("tcu")
                if isinstance(rcu, int) and isinstance(tcu, int):
                    rmu_label = (rcu << 8) | tcu
            dcu_id = frame.sid if frame.sid is not None else "-"
            lines.append(f"[{timestamp}] INFO  - DCU ID     : {dcu_id}")
            lines.append(f"[{timestamp}] INFO  - ============================[{chr(frame.cmd).lower()}]")
            lines.append(f"[{timestamp}] INFO  - RMU ID      : {rmu_label}")
            if parsed.get("timestamp"):
                lines.append(f"[{timestamp}] INFO  - TIME        : {parsed['timestamp']}")
            dumps = parsed.get("dumps", [])
            for idx, dump in enumerate(dumps, start=1):
                raw_type = dump.get("meter_type_raw")
                if isinstance(raw_type, int):
                    lines.append(f"[{timestamp}] INFO  - M TYPE      : {raw_type:02X}")
                label = f"MDATA{idx}"
                lines.append(f"[{timestamp}] INFO  - {label:<11}: {self._format_meter_dump(dump)}")
            if not dumps:
                lines.append(f"[{timestamp}] INFO  - MDATA1      : -")
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

    def _meter_type_label_to_code(self, label: str) -> int:
        mapping = {
            "전기(EM)": 0x01,
            "수도(WM)": 0x02,
            "온수(HM)": 0x04,
            "가스(GM)": 0x08,
            "열량(CM)": 0x10,
        }
        return mapping.get(label, 0x01)

    def _meter_type_code_to_label(self, code: int) -> str:
        for bit, label in (
            (0x01, "전기(EM)"),
            (0x02, "수도(WM)"),
            (0x04, "온수(HM)"),
            (0x08, "가스(GM)"),
            (0x10, "열량(CM)"),
        ):
            if code & bit:
                return label
        return self.rmu_mtype_choices[0]

    def _protocol_label_to_code(self, label: str) -> int:
        try:
            prefix = label.split("_", 1)[0]
            return int(prefix)
        except (ValueError, IndexError):
            return 0

    def _protocol_code_to_label(self, code: int) -> str:
        for option in self.protocol_type_choices:
            try:
                if int(option.split("_", 1)[0]) == code:
                    return option
            except (ValueError, IndexError):
                continue
        return self.protocol_type_choices[0]

    def _pulse_meter_type_value(self) -> int:
        return self._meter_type_label_to_code(self.rmu_mtype_var.get())

    def _update_rmu_table_data(self, parsed: Dict[str, object]) -> None:
        for key, var in self.rmu_data_vars.items():
            if key == "meter_id":
                var.set("")
            elif key == "firmware":
                var.set("-")
            else:
                var.set("-")
        self.rmu_meter_type_var.set("전체")
        rmu = parsed.get("rmu_id", {})
        meter_id_display = rmu
        rcu = tcu = None
        if isinstance(rmu, dict):
            rcu = rmu.get("rcu")
            tcu = rmu.get("tcu")
            if isinstance(rcu, int) and isinstance(tcu, int):
                meter_id_display = f"{rcu}-{tcu}"
        self.rmu_data_vars["meter_id"].set(str(meter_id_display))

        if isinstance(rcu, int) and isinstance(tcu, int):
            info = self.rmu_info_cache.get((rcu, tcu))
            if info:
                if info.get("firmware_version"):
                    self.rmu_data_vars["firmware"].set(str(info.get("firmware_version")))
        dumps = parsed.get("dumps", [])
        mapping = {
            "electric": ("em", 0x01, "전기(EM)"),
            "water": ("wm", 0x02, "수도(WM)"),
            "hot_water": ("hm", 0x04, "온수(HM)"),
            "gas": ("gm", 0x08, "가스(GM)"),
            "heat": ("cm", 0x10, "열량(CM)"),
        }
        selected_labels: set[str] = set()
        for dump in dumps:
            labels_for_dump: set[str] = set()
            keys_for_dump: set[str] = set()
            mt_raw = dump.get("meter_type_raw")
            if isinstance(mt_raw, int):
                for name, (key, bit, label) in mapping.items():
                    if mt_raw & bit:
                        keys_for_dump.add(key)
                        labels_for_dump.add(label)
            names = dump.get("meter_type")
            if isinstance(names, list):
                for name in names:
                    entry = mapping.get(name)
                    if entry:
                        key, _bit, label = entry
                        keys_for_dump.add(key)
                        labels_for_dump.add(label)
            value = self._format_meter_dump(dump)
            for key in keys_for_dump:
                current = self.rmu_data_vars[key].get()
                if not current or current == "-":
                    self.rmu_data_vars[key].set(value)
                else:
                    self.rmu_data_vars[key].set(f"{current}, {value}")
            selected_labels.update(labels_for_dump)
        if len(selected_labels) == 1:
            label = next(iter(selected_labels))
            self.rmu_meter_type_var.set(label if label in self.rmu_meter_type_options else "전체")
        elif selected_labels:
            self.rmu_meter_type_var.set("전체")

    def _log_login_info(self, frame: Frame, parsed: Dict[str, object]) -> None:
        path = self.base_path / "Login.txt"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dcu_id = frame.sid if frame.sid is not None else "-"
        line = (
            f"{timestamp},DCU ID={dcu_id},F/W={parsed.get('firmware_version')},"
            f"IP={parsed.get('dcu_ip')},PORT={parsed.get('dcu_port')}\n"
        )
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def _load_settings(self) -> None:
        if not self.settings_path.exists():
            return
        config = configparser.ConfigParser()
        config.read(self.settings_path, encoding="utf-8")
        if config.has_section("connection"):
            sec = config["connection"]
            key_map = {
                "host": self.host_var,
                "port": self.port_var,
                "did": self.did_var,
                "sid": self.sid_var,
                "rcu": self.rcu_var,
                "tcu": self.tcu_var,
                "fep_ip": self.fep_ip_var,
                "fep_port": self.fep_port_var,
                "dcu_ip": self.dcu_ip_var,
                "dcu_port": self.dcu_port_var,
                "dcu_send": self.dcu_send_period_var,
                "dcu_log": self.dcu_log_period_var,
                "dcu_retry": self.dcu_retry_var,
                "periodic_interval": self.periodic_interval_var,
                "pulse_value": self.pulse_value_var,
            }
            for key, var in key_map.items():
                if key in sec:
                    var.set(sec[key])
            if "auto_ack" in sec:
                self.auto_ack_var.set(sec.getboolean("auto_ack", fallback=True))
            if "sid_match" in sec:
                self.sid_match_var.set(sec.getboolean("sid_match", fallback=True))
            if "rmu_mtype_choice" in sec:
                if sec["rmu_mtype_choice"] in self.rmu_mtype_choices:
                    self.rmu_mtype_var.set(sec["rmu_mtype_choice"])
            elif "rmu_mtype" in sec:
                try:
                    self.rmu_mtype_var.set(self._meter_type_code_to_label(int(sec["rmu_mtype"], 0)))
                except ValueError:
                    pass
            if "rmu_protocol" in sec:
                self.rmu_protocol_var.set(self._protocol_code_to_label(self._protocol_label_to_code(sec["rmu_protocol"])))

    def _save_settings(self) -> None:
        config = configparser.ConfigParser()
        config["connection"] = {
            "host": self.host_var.get(),
            "port": self.port_var.get(),
            "did": self.did_var.get(),
            "sid": self.sid_var.get(),
            "rcu": self.rcu_var.get(),
            "tcu": self.tcu_var.get(),
            "fep_ip": self.fep_ip_var.get(),
            "fep_port": self.fep_port_var.get(),
            "auto_ack": str(self.auto_ack_var.get()),
            "sid_match": str(self.sid_match_var.get()),
            "dcu_ip": self.dcu_ip_var.get(),
            "dcu_port": self.dcu_port_var.get(),
            "dcu_send": self.dcu_send_period_var.get(),
            "dcu_log": self.dcu_log_period_var.get(),
            "dcu_retry": self.dcu_retry_var.get(),
            "rmu_mtype_choice": self.rmu_mtype_var.get(),
            "rmu_protocol": self.rmu_protocol_var.get(),
            "periodic_interval": self.periodic_interval_var.get(),
            "pulse_value": self.pulse_value_var.get(),
        }
        self.base_path.mkdir(parents=True, exist_ok=True)
        if self.settings_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup = self.settings_path.with_name(f"{timestamp}_FepServer_init.ini")
            try:
                if backup.exists():
                    backup.unlink()
                self.settings_path.replace(backup)
            except OSError:
                pass
        with self.settings_path.open("w", encoding="utf-8") as fh:
            config.write(fh)

    def _on_close(self) -> None:
        self.client.disconnect()
        self._stop_server()
        self._save_settings()
        self.root.destroy()

    def _auto_ack(self, frame: Frame, transport: Transport, session: Dict[str, object]) -> None:
        if session.get("suppress_ack_once"):
            session.pop("suppress_ack_once", None)
            return

        dest = frame.sid
        our_sid = self._resolve_sid(dest)
        dest = frame.sid
        if dest is None:
            return
        if frame.cmd in {
            Command.ACK,
            Command.NACK,
        }:
            return
        if frame.cmd in {
            Command.DCU_INFO_RESPONSE,
            Command.RMU_INFO_RESPONSE,
            Command.RMU_LIST_RESPONSE,
            Command.CURRENT_READING_RESPONSE,
            Command.PERIODIC_READING_RESPONSE,
            Command.SAVED_READING_RESPONSE,
            Command.EVENT_NOTIFICATION,
            Command.MICRO_TEMP_INFO,
        }:
            try:
                transport.send_command(Command.ACK, b"", did=dest, sid=our_sid)
                self._record_tx(Command.ACK, b"", dest, our_sid, extra="auto")
            except RuntimeError:
                pass

    def _start_server(self, port: int) -> None:
        self.server.configure("0.0.0.0", port)
        self.server.start()
        self._log(f"FEP server listening on 0.0.0.0:{port}")

    def _stop_server(self) -> None:
        self.server.stop()
        if self.server_session_token is not None:
            self._remove_session(("server", self.server_session_token))
            self.server_session_token = None


def main() -> None:
    root = tk.Tk()
    app = DcuApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
