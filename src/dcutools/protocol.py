from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

SOF = 0xE1
EOF = 0xE2
DLE = 0x10
DLE_OFFSET = 0x10
DEFAULT_VERSION = 0x10
CHECKSUM_PRIMARY = 0x00
CHECKSUM_FALLBACK = 0xFF


class Command(enum.IntEnum):
    """Known command codes for the FEP-DCU protocol."""

    ACK = 0x41
    DCU_INFO_REQUEST = 0x42
    DCU_CONFIGURE = 0x43
    RMU_INFO_REQUEST = 0x44
    RMU_CONFIGURE = 0x45
    RMU_LIST_REQUEST = 0x46
    CURRENT_READING_REQUEST = 0x47
    SAVED_READING_REQUEST = 0x48
    PERIODIC_READING_REQUEST = 0x49
    EVENT_REQUEST = 0x4A
    RMU_PULSE_INIT = 0x4B
    MICRO_TEMP_SET = 0x4C

    NACK = 0x61
    DCU_INFO_RESPONSE = 0x62
    RMU_INFO_RESPONSE = 0x64
    RMU_LIST_RESPONSE = 0x66
    CURRENT_READING_RESPONSE = 0x67
    SAVED_READING_RESPONSE = 0x68
    PERIODIC_READING_RESPONSE = 0x69
    EVENT_NOTIFICATION = 0x6A
    MICRO_TEMP_INFO = 0x6C


@dataclass(frozen=True)
class Frame:
    """Represents a decoded frame without SOF/EOF markers."""

    ver: int
    did: int
    sid: int
    length: int
    cmd: int
    data: bytes
    checksum: int
    raw: bytes

    def ensure_checksum(self) -> bool:
        if calc_checksum(self.raw[:-1], initial=CHECKSUM_PRIMARY) == self.checksum:
            return True
        if calc_checksum(self.raw[:-1], initial=CHECKSUM_FALLBACK) == self.checksum:
            return True
        return False


class FrameEncoder:
    """Utility for building frames with checksum and DLE escaping."""

    def __init__(
        self,
        version: int = DEFAULT_VERSION,
        did: int = 0x0000,
        sid: int = 0x0000,
        *,
        checksum_initial: int = CHECKSUM_PRIMARY,
    ) -> None:
        self.version = version
        self.did = did
        self.sid = sid
        self.checksum_initial = checksum_initial & 0xFF

    def build(
        self,
        cmd: int,
        data: bytes = b"",
        *,
        version: Optional[int] = None,
        did: Optional[int] = None,
        sid: Optional[int] = None,
    ) -> bytes:
        ver = self.version if version is None else version
        did_val = self.did if did is None else did
        sid_val = self.sid if sid is None else sid

        frame = bytearray()
        frame.append(ver & 0xFF)
        frame.extend(did_val.to_bytes(2, "big"))
        frame.extend(sid_val.to_bytes(2, "big"))

        length = len(data) + 2  # CMD + DATA + CHK
        frame.append(length & 0xFF)
        frame.append(cmd & 0xFF)
        frame.extend(data)

        checksum = calc_checksum(frame, initial=self.checksum_initial)
        frame.append(checksum)

        escaped = apply_dle(bytes(frame))
        return bytes([SOF]) + escaped + bytes([EOF])


class FrameDecoder:
    """Streaming decoder that yields frames as byte payloads."""

    def __init__(self) -> None:
        self._in_frame = False
        self._escape = False
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> List[bytes]:
        frames: List[bytes] = []
        for byte in chunk:
            if not self._in_frame:
                if byte == SOF:
                    self._in_frame = True
                    self._buffer.clear()
                    self._escape = False
                continue

            if self._escape:
                self._buffer.append((byte - DLE_OFFSET) & 0xFF)
                self._escape = False
                continue

            if byte == DLE:
                self._escape = True
                continue

            if byte == EOF:
                frames.append(bytes(self._buffer))
                self._in_frame = False
                self._escape = False
                self._buffer.clear()
                continue

            self._buffer.append(byte)

        return frames


def parse_frame(payload: bytes) -> Frame:
    if len(payload) < 8:
        raise ValueError("payload too short to be a frame")

    ver = payload[0]
    did = int.from_bytes(payload[1:3], "big")
    sid = int.from_bytes(payload[3:5], "big")
    length = payload[5]

    tail = payload[6:]
    if len(tail) < 2:
        raise ValueError("invalid payload length")
    if len(tail) == length:
        cmd = tail[0]
        data = tail[1:-1]
        checksum = tail[-1]
    elif len(tail) == length + 1:
        cmd = tail[0]
        data_len = max(length - 1, 0)
        data_end = 1 + data_len
        if data_end >= len(tail):
            raise ValueError("invalid length field")
        data = tail[1:data_end]
        checksum = tail[data_end]
    else:
        raise ValueError("invalid length field")

    frame = Frame(ver=ver, did=did, sid=sid, length=length, cmd=cmd, data=data, checksum=checksum, raw=payload)
    if not frame.ensure_checksum():
        raise ValueError("checksum mismatch")
    return frame


class PacketParser:
    """Parse known payload structures into friendly dictionaries."""

    def parse(self, frame: Frame) -> Dict[str, Any]:
        handler = _FRAME_HANDLERS.get(frame.cmd)
        if handler is None:
            return {
                "command": describe_command(frame.cmd),
                "raw_data": frame.data.hex(),
            }
        return handler(frame)


def _handle_dcu_info(frame: Frame) -> Dict[str, Any]:
    data = frame.data
    if len(data) < 26:
        raise ValueError("dcu info payload too short")

    t_raw = data[0:6]
    fw_raw = data[6]
    fep_ip = data[7:11]
    fep_port = int.from_bytes(data[11:15], "little")
    dcu_ip = data[15:19]
    dcu_port = int.from_bytes(data[19:23], "little")
    send_period = int.from_bytes(data[23:25], "little")
    log_period = int.from_bytes(data[25:27], "little") if len(data) >= 27 else None
    retry = data[27] if len(data) >= 28 else None
    power_state = data[28] if len(data) >= 29 else None

    return {
        "command": "DCU info",
        "timestamp": bcd_datetime(t_raw),
        "firmware_version": bcd_version(fw_raw),
        "fep_ip": format_ipv4(fep_ip),
        "fep_port": fep_port,
        "dcu_ip": format_ipv4(dcu_ip),
        "dcu_port": dcu_port,
        "send_period_min": send_period,
        "log_period_min": log_period,
        "retry_count": retry,
        "power_state": "ON" if power_state else "OFF" if power_state is not None else None,
    }


def _handle_rmu_info(frame: Frame) -> Dict[str, Any]:
    data = memoryview(frame.data)
    items: List[Dict[str, Any]] = []
    offset = 0
    entry_size = 20
    while offset + entry_size <= len(data):
        chunk = data[offset:offset + entry_size]
        items.append({
            "rmu_id": parse_rmu_id(bytes(chunk[0:2])),
            "firmware_version": bcd_version(chunk[2]),
            "measured_at": bcd_datetime(bytes(chunk[3:9])),
            "network_index": int.from_bytes(bytes(chunk[9:11]), "big"),
            "meter_type": decode_meter_type(chunk[11]),
            "meter_type_raw": chunk[11],
            "write_period_h": chunk[12],
            "tx_period_h": chunk[13],
            "tx_delay_s": int.from_bytes(bytes(chunk[14:16]), "big"),
            "energy_meter_type": chunk[16],
            "meter_protocol": chunk[17],
            "meter_interface": chunk[18],
            "power_type": chunk[19],
        })
        offset += entry_size

    return {
        "command": "RMU info",
        "items": items,
        "raw_data": frame.data[offset:].hex() if offset < len(data) else None,
    }


def _handle_rmu_list(frame: Frame) -> Dict[str, Any]:
    ids = [parse_rmu_id(frame.data[i:i + 2]) for i in range(0, len(frame.data), 2) if i + 2 <= len(frame.data)]
    return {
        "command": "RMU list",
        "rmu_ids": ids,
    }


def _handle_meter_read(frame: Frame) -> Dict[str, Any]:
    data = memoryview(frame.data)
    if len(data) < 9:
        raise ValueError("meter read payload too short")

    rmu_id = parse_rmu_id(bytes(data[0:2]))
    timestamp = bcd_datetime(bytes(data[2:8]))
    cnt = data[8]
    dumps: List[Dict[str, Any]] = []
    offset = 9
    for _ in range(cnt):
        try:
            dump, offset = _parse_meter_dump(data, offset)
        except ValueError as exc:
            dumps.append({
                "error": str(exc),
                "raw_tail": bytes(data[offset:]).hex(),
            })
            break
        dumps.append(dump)

    return {
        "command": "meter reading",
        "rmu_id": rmu_id,
        "timestamp": timestamp,
        "dumps": dumps,
        "count": cnt,
        "remaining": bytes(data[offset:]).hex() if offset < len(data) else None,
    }


def _handle_event(frame: Frame) -> Dict[str, Any]:
    if len(frame.data) < 3:
        raise ValueError("event payload too short")
    return {
        "command": "event",
        "rmu_id": parse_rmu_id(frame.data[0:2]),
        "event_code": frame.data[2],
    }


def _handle_saved_reading(frame: Frame) -> Dict[str, Any]:
    data = memoryview(frame.data)
    if len(data) < 11:
        raise ValueError("saved reading payload too short")

    rmu_id = parse_rmu_id(bytes(data[0:2]))
    timestamp = bcd_datetime(bytes(data[2:8]))

    offset = 8
    try:
        current_dump, offset = _parse_meter_dump(data, offset, expect_status=False)
    except ValueError as exc:
        raise ValueError(f"failed to parse current reading portion: {exc}") from exc

    if offset >= len(data):
        raise ValueError("saved reading payload missing count")
    count = data[offset]
    offset += 1

    log_period = None
    if offset + 2 <= len(data):
        log_period = int.from_bytes(bytes(data[offset:offset + 2]), "big")
        offset += 2

    meter_type_raw = current_dump.get("meter_type_raw", 0)
    history, consumed, truncated = _parse_saved_records(data[offset:], meter_type_raw, count)
    offset += consumed

    result: Dict[str, Any] = {
        "command": "saved meter reading",
        "rmu_id": rmu_id,
        "timestamp": timestamp,
        "count": count,
        "log_period_min": log_period,
        "current": current_dump,
        "history": history,
    }
    if truncated:
        result["history_truncated"] = True
    if meter_type_raw:
        result["meter_type_raw"] = meter_type_raw
        result["meter_type"] = decode_meter_type(meter_type_raw)
    if offset < len(data):
        result["remaining"] = bytes(data[offset:]).hex()
    return result


def _handle_ack(frame: Frame) -> Dict[str, Any]:
    return {
        "command": "ack",
        "did": frame.did,
        "sid": frame.sid,
        "data": frame.data.hex() if frame.data else None,
    }


def _handle_nack(frame: Frame) -> Dict[str, Any]:
    code = frame.data[0] if frame.data else None
    reasons = {
        0x01: "checksum_error",
        0x02: "frame_error",
        0x03: "busy",
    }
    return {
        "command": "nack",
        "did": frame.did,
        "sid": frame.sid,
        "code": code,
        "reason": reasons.get(code, None),
        "data": frame.data.hex() if len(frame.data) > 1 else None,
    }


def _handle_micro_temp(frame: Frame) -> Dict[str, Any]:
    data = frame.data
    if len(data) < 7:
        raise ValueError("micro temperature payload too short")

    rmu = parse_rmu_id(data[0:2])
    mode_map = {0: "heat", 1: "cool"}
    fan_map = {0: "off", 1: "on"}
    speed_map = {0: "off", 1: "low", 2: "mid", 3: "high"}

    return {
        "command": "micro temperature info",
        "rmu_id": rmu,
        "mode_code": data[2],
        "mode": mode_map.get(data[2]),
        "fan_switch_code": data[3],
        "fan_switch": fan_map.get(data[3]),
        "fan_speed_code": data[4],
        "fan_speed": speed_map.get(data[4]),
        "set_temp_c": data[5],
        "current_temp_c": data[6],
        "raw_data": frame.data.hex(),
    }


_FRAME_HANDLERS = {
    Command.ACK: _handle_ack,
    Command.NACK: _handle_nack,
    Command.DCU_INFO_RESPONSE: _handle_dcu_info,
    Command.RMU_INFO_RESPONSE: _handle_rmu_info,
    Command.RMU_LIST_RESPONSE: _handle_rmu_list,
    Command.CURRENT_READING_RESPONSE: _handle_meter_read,
    Command.PERIODIC_READING_RESPONSE: _handle_meter_read,
    Command.SAVED_READING_RESPONSE: _handle_saved_reading,
    Command.EVENT_NOTIFICATION: _handle_event,
    Command.MICRO_TEMP_INFO: _handle_micro_temp,
}


def apply_dle(payload: bytes) -> bytes:
    escaped = bytearray()
    for byte in payload:
        if byte in (SOF, EOF, DLE):
            escaped.append(DLE)
            escaped.append((byte + DLE_OFFSET) & 0xFF)
        else:
            escaped.append(byte)
    return bytes(escaped)


def calc_checksum(data: Iterable[int], *, initial: int = 0) -> int:
    total = initial & 0xFF
    for value in data:
        total = (total + value) & 0xFF
    return total


def bcd_datetime(data: bytes) -> Optional[datetime]:
    if len(data) != 6:
        return None
    try:
        year = 2000 + bcd_byte(data[0])
        month = bcd_byte(data[1])
        day = bcd_byte(data[2])
        hour = bcd_byte(data[3])
        minute = bcd_byte(data[4])
        second = bcd_byte(data[5])
        return datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None


def bcd_version(byte: int) -> Optional[str]:
    high = (byte >> 4) & 0xF
    low = byte & 0xF
    if high > 9 or low > 9:
        return None
    return f"V{high}.{low}"


def bcd_byte(byte: int) -> int:
    high = (byte >> 4) & 0x0F
    low = byte & 0x0F
    if high > 9 or low > 9:
        raise ValueError("invalid BCD digit")
    return high * 10 + low


def format_ipv4(data: bytes) -> str:
    if len(data) != 4:
        return "".join(f"{b:02X}" for b in data)
    return ".".join(str(b) for b in data)


def decode_meter_type(value: int) -> List[str]:
    names = []
    mapping = {
        0x01: "electric",
        0x02: "water",
        0x04: "hot_water",
        0x08: "gas",
        0x10: "heat",
    }
    for bit, name in mapping.items():
        if value & bit:
            names.append(name)
    return names or [f"0x{value:02X}"]


def resolve_data_length(dif: int) -> int:
    code = dif & 0x0F
    mapping = {
        0x00: 0,
        0x01: 1,
        0x02: 2,
        0x03: 3,
        0x04: 4,
        0x05: 4,
        0x06: 6,
        0x07: 8,
        0x08: 0,
        0x09: 1,
        0x0A: 2,
        0x0B: 3,
        0x0C: 4,
        0x0D: 0,
        0x0E: 6,
        0x0F: 0,
    }
    return mapping.get(code, 0)


def interpret_meter_value(dif: int, vif: int, value: bytes) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        digits = decode_bcd_digits(value)
        number = int("".join(digits)) if digits else None
    except ValueError:
        number = None

    unit, scale = interpret_vif(vif)
    if number is None:
        return None if unit is None else {"unit": unit, "scale": scale, "raw": value.hex()}
    if scale is not None:
        adjusted = number * (10 ** scale)
    else:
        adjusted = number
    return {
        "value": adjusted,
        "unit": unit,
        "scale": scale,
        "digits": digits,
    }


def decode_bcd_digits(value: bytes) -> List[str]:
    digits: List[str] = []
    for byte in reversed(value):
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        if high <= 9:
            digits.append(str(high))
        if low <= 9:
            digits.append(str(low))
    digits.reverse()
    return digits


def decode_bcd_value(value: bytes, decimals: int = 0) -> Optional[float]:
    digits = decode_bcd_digits(value)
    if not digits:
        return None
    try:
        integer_value = int("".join(digits))
    except ValueError:
        return None
    if decimals > 0:
        return integer_value / (10 ** decimals)
    return float(integer_value)


def interpret_vif(vif: int) -> Tuple[Optional[str], Optional[int]]:
    if (vif & 0xE0) == 0x00:
        exponent = ((vif & 0x07) - 3)
        return "Wh", exponent
    if (vif & 0xE0) == 0x20:
        exponent = ((vif & 0x07) - 6)
        return "m3", exponent
    if (vif & 0xE0) == 0x50:
        exponent = ((vif & 0x03) - 3)
        return "°C", exponent
    return None, None


def describe_command(cmd: int) -> str:
    try:
        return Command(cmd).name
    except ValueError:
        return f"0x{cmd:02X}"


def build_rmu_id(rcu_id: int, tcu_id: int) -> bytes:
    return bytes([rcu_id & 0xFF, tcu_id & 0xFF])


def parse_rmu_id(raw: bytes) -> Dict[str, int]:
    if len(raw) != 2:
        return {"raw": raw.hex()}
    return {"rcu": raw[0], "tcu": raw[1]}


def pack_datetime(dt: datetime) -> bytes:
    return bytes([
        pack_bcd(dt.year % 100),
        pack_bcd(dt.month),
        pack_bcd(dt.day),
        pack_bcd(dt.hour),
        pack_bcd(dt.minute),
        pack_bcd(dt.second),
    ])


def pack_bcd(value: int) -> int:
    if value < 0 or value > 99:
        raise ValueError("value outside BCD range")
    return ((value // 10) << 4) | (value % 10)


def _parse_meter_dump(data: memoryview, offset: int, *, expect_status: bool = True) -> Tuple[Dict[str, Any], int]:
    if offset >= len(data):
        raise ValueError("meter dump incomplete (missing meter type)")
    meter_type_val = data[offset]
    offset += 1

    if offset >= len(data):
        raise ValueError("meter dump incomplete (missing DIF)")
    dif = data[offset]
    offset += 1

    vif = 0
    if offset < len(data):
        vif = data[offset]
        offset += 1

    data_length = resolve_data_length(dif)
    value_end = offset + data_length
    if value_end > len(data):
        raw_value = bytes(data[offset:])
        value_end = len(data)
    else:
        raw_value = bytes(data[offset:value_end])
    offset = value_end

    status = None
    if expect_status and offset < len(data):
        status = data[offset]
        offset += 1

    dump: Dict[str, Any] = {
        "meter_type_raw": meter_type_val,
        "meter_type": decode_meter_type(meter_type_val),
        "dif": dif,
        "vif": vif,
        "raw_value": raw_value.hex(),
        "interpreted": interpret_meter_value(dif, vif, raw_value),
    }
    if status is not None:
        dump["status"] = status
    return dump, offset


def _parse_saved_records(buffer: memoryview, meter_type: int, count: int) -> Tuple[List[Dict[str, Any]], int, bool]:
    if count <= 0:
        return [], 0, False

    records: List[Dict[str, Any]] = []
    offset = 0
    truncated = False
    meter_names = set(decode_meter_type(meter_type))
    is_heat = "heat" in meter_names
    is_water_family = any(name in {"water", "hot_water", "gas"} for name in meter_names)
    is_electric = "electric" in meter_names

    for index in range(count):
        if is_heat:
            required = 12
            if offset + required > len(buffer):
                truncated = True
                break
            chunk = bytes(buffer[offset:offset + required])
            records.append({
                "index": index,
                "energy_mwh": decode_bcd_value(chunk[0:4], 3),
                "volume_m3": decode_bcd_value(chunk[4:8], 3),
                "supply_temp_c": decode_bcd_value(chunk[8:10], 2),
                "return_temp_c": decode_bcd_value(chunk[10:12], 2),
                "raw": chunk.hex(),
            })
            offset += required
            continue

        length = 4
        if offset + length > len(buffer):
            truncated = True
            break
        chunk = bytes(buffer[offset:offset + length])
        record: Dict[str, Any] = {"index": index, "raw": chunk.hex()}
        if is_water_family:
            record["volume_m3"] = decode_bcd_value(chunk, 3)
        elif is_electric:
            record["energy_wh"] = decode_bcd_value(chunk, 3)
        records.append(record)
        offset += length

    return records, offset, truncated
