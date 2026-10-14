"""Async OpenWebNet and SIP client for BTicino HOMETOUCH."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import random
import secrets
import socket
import ssl
import time
import uuid
from typing import Callable

from .const import (
    DEFAULT_DOOR_ADDR,
    DEFAULT_GATE_ADDR,
    DEFAULT_PORT,
    DEFAULT_SIP_PORT,
    DEFAULT_SIP_SERVER,
    FRAME_DOOR_LOCK_OFF,
    FRAME_DOOR_LOCK_ON,
    FRAME_GATE_OFF,
    FRAME_GATE_ON,
    FRAME_STAIR_LIGHT,
    OWN_ACK,
    OWN_CALL_END_PATTERN,
    OWN_CALL_PATTERN,
    OWN_CMD_SESSION,
    OWN_MONITOR_SESSION,
    OWN_NACK,
)

_LOGGER = logging.getLogger(__name__)


def _decode_wire_hex(s: str) -> str:
    """Decode OpenWebNet 4-chars-per-byte format to lowercase hex string."""
    hex_str = ""
    for i in range(0, len(s), 4):
        chunk = s[i : i + 4]
        if len(chunk) == 4:
            try:
                high = int(chunk[0:2])
                low = int(chunk[2:4])
                val = (high << 4) | low
                hex_str += f"{val:02x}"
            except ValueError:
                pass
    return hex_str


def _encode_wire_hex(hex_str: str) -> str:
    """Encode lowercase hex string to OpenWebNet 4-chars-per-byte format."""
    wire = ""
    try:
        raw_bytes = bytes.fromhex(hex_str)
        for b in raw_bytes:
            high = b >> 4
            low = b & 0x0F
            wire += f"{high:02d}{low:02d}"
    except Exception:
        pass
    return wire


def _calc_hmac_sha256_response(ra_wire: str, password: str) -> tuple[str, str]:
    """Calculate HMAC-SHA256 authentication response according to Legrand OpenWebNet specification.
    Returns (rb_wire, hmac_wire).
    """
    ra_hex = _decode_wire_hex(ra_wire)
    rb_bytes = secrets.token_bytes(32)
    rb_hex = rb_bytes.hex()
    rb_wire = _encode_wire_hex(rb_hex)

    kab_hex = hashlib.sha256(password.encode("utf-8")).hexdigest()
    A = "736F70653E"  # Client identity (ASCII 'sopen>')
    B = "636F70653E"  # Server identity (ASCII 'copen>')

    data_to_hash = (ra_hex + rb_hex + A + B + kab_hex).encode("ascii")
    hmac_digest = hashlib.sha256(data_to_hash).hexdigest()
    hmac_wire = _encode_wire_hex(hmac_digest)

    return rb_wire, hmac_wire


def _parse_digest_challenge(response_text: str) -> dict[str, str]:
    """Parse HTTP/SIP Digest challenge header."""
    for line in response_text.split("\r\n"):
        lower = line.lower()
        if lower.startswith("proxy-authenticate:") or lower.startswith("www-authenticate:"):
            auth_val = line.split(":", 1)[1].strip()
            parts = {}
            for item in auth_val.replace("Digest ", "").split(","):
                if "=" in item:
                    k, v = item.split("=", 1)
                    parts[k.strip()] = v.strip().strip('"')
            return parts
    return {}


def _compute_digest(method: str, uri: str, realm: str, nonce: str, username: str, password: str, qop: str | None = None, opaque: str | None = None) -> str:
    """Compute RFC 2617 Digest response with qop=auth support."""
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop and "auth" in qop:
        nc = "00000001"
        cnonce = uuid.uuid4().hex[:8]
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        auth_hdr = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}", algorithm=MD5, '
            f'cnonce="{cnonce}", nc={nc}, qop=auth'
        )
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth_hdr = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}", algorithm=MD5'
        )
    if opaque:
        auth_hdr += f', opaque="{opaque}"'
    return auth_hdr


class HometouchClient:
    """Client for communicating with BTicino HOMETOUCH via LAN and SIP TLS."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        password: str | None = None,
        sip_user: str | None = None,
        sip_pass: str | None = None,
        sip_domain: str | None = None,
        sip_server: str = DEFAULT_SIP_SERVER,
        sip_port: int = DEFAULT_SIP_PORT,
        cert_file: str | None = None,
        key_file: str | None = None,
        gate_addr: str = DEFAULT_GATE_ADDR,
        door_addr: str = DEFAULT_DOOR_ADDR,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        if sip_user and "@" in sip_user:
            user_part, domain_part = sip_user.split("@", 1)
            self.sip_user = user_part
            self.sip_domain = sip_domain or domain_part
        else:
            self.sip_user = sip_user
            self.sip_domain = sip_domain

        self.sip_pass = sip_pass
        self.sip_server = sip_server
        self.sip_port = sip_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.gate_addr = gate_addr
        self.door_addr = door_addr

        self._listeners: list[Callable[[str, bool], None]] = []
        self._is_call_active = False
        self._running = False
        self._monitor_task: asyncio.Task | None = None
        self._sip_listener_task: asyncio.Task | None = None

    @property
    def is_call_active(self) -> bool:
        """Return True if doorbell call is active."""
        return self._is_call_active

    def register_listener(self, cb: Callable[[str, bool], None]) -> Callable[[], None]:
        """Register callback for event updates."""
        self._listeners.append(cb)
        def unsubscribe():
            if cb in self._listeners:
                self._listeners.remove(cb)
        return unsubscribe

    def _notify_event(self, event_type: str, state: bool) -> None:
        """Notify registered listeners of an event."""
        for cb in self._listeners:
            try:
                cb(event_type, state)
            except Exception as err:
                _LOGGER.error("Error in listener callback: %s", err)

    def _sync_send_sip_command(self, body: str) -> bool:
        """Send command encapsulated in SIP MESSAGE over mTLS (Blocking)."""
        if not self.cert_file or not self.key_file or not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            _LOGGER.error("Certificato o chiave SIP mancante (%s, %s)", self.cert_file, self.key_file)
            return False

        target_uri = f"sip:MHT@{self.sip_domain}"
        call_id = str(uuid.uuid4())
        cseq = 1

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            ssl_sock = ctx.wrap_socket(s, server_hostname=self.sip_server)
            ssl_sock.connect((self.sip_server, self.sip_port))

            # 1. Send SIP REGISTER
            branch = "z9hG4bK" + uuid.uuid4().hex[:12]
            tag = uuid.uuid4().hex[:8]
            reg_msg = (
                f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} REGISTER\r\n"
                f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                f"Expires: 300\r\n"
                f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            ssl_sock.sendall(reg_msg.encode())
            resp = ssl_sock.recv(4096).decode(errors="replace")

            if "401" in resp or "407" in resp:
                chal = _parse_digest_challenge(resp)
                auth_hdr = _compute_digest("REGISTER", f"sip:{self.sip_domain}", chal.get("realm", self.sip_domain), chal.get("nonce", ""), self.sip_user or "", self.sip_pass or "", qop=chal.get("qop"), opaque=chal.get("opaque"))
                cseq += 1
                branch = "z9hG4bK" + uuid.uuid4().hex[:12]
                reg_auth = (
                    f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                    f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq} REGISTER\r\n"
                    f"Authorization: {auth_hdr}\r\n"
                    f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                    f"Expires: 300\r\n"
                    f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                ssl_sock.sendall(reg_auth.encode())
                ssl_sock.recv(4096)

            # 2. Send Initial MESSAGE
            cseq += 1
            branch = "z9hG4bK" + uuid.uuid4().hex[:12]
            tag = uuid.uuid4().hex[:8]
            body_bytes = body.encode("utf-8")
            msg = (
                f"MESSAGE {target_uri} SIP/2.0\r\n"
                f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                f"To: <{target_uri}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} MESSAGE\r\n"
                f"Content-Type: text/plain\r\n"
                f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                f"Content-Length: {len(body_bytes)}\r\n\r\n"
                f"{body}"
            )
            ssl_sock.sendall(msg.encode())

            # Read response
            ssl_sock.settimeout(4.0)
            chal = {}
            while True:
                try:
                    m_resp = ssl_sock.recv(4096).decode(errors="replace")
                    if not m_resp:
                        break
                    if "407 Proxy Authentication Required" in m_resp or "401 Unauthorized" in m_resp:
                        chal = _parse_digest_challenge(m_resp)
                        break
                    elif "200 Ok" in m_resp or "200 OK" in m_resp:
                        ssl_sock.close()
                        return True
                except socket.timeout:
                    break

            if chal:
                realm = chal.get("realm", self.sip_domain)
                nonce = chal.get("nonce", "")
                qop = chal.get("qop")
                opaque = chal.get("opaque")
                auth_hdr = _compute_digest("MESSAGE", target_uri, realm, nonce, self.sip_user or "", self.sip_pass or "", qop=qop, opaque=opaque)

                cseq += 1
                branch = "z9hG4bK" + uuid.uuid4().hex[:12]
                auth_msg = (
                    f"MESSAGE {target_uri} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                    f"To: <{target_uri}>\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq} MESSAGE\r\n"
                    f"Proxy-Authorization: {auth_hdr}\r\n"
                    f"Content-Type: text/plain\r\n"
                    f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n\r\n"
                    f"{body}"
                )
                ssl_sock.sendall(auth_msg.encode())

                start_wait = time.time()
                while time.time() - start_wait < 5.0:
                    try:
                        final_resp = ssl_sock.recv(4096).decode(errors="replace")
                        if "200 Ok" in final_resp or "200 OK" in final_resp:
                            ssl_sock.close()
                            return True
                    except socket.timeout:
                        break

            ssl_sock.close()
            return True
        except Exception as err:
            _LOGGER.error("Errore invio SIP comando %s: %s", body, err)
            return False

    async def send_sip_command(self, body: str) -> bool:
        """Async wrapper for sending a SIP command."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_send_sip_command, body)

    async def open_gate(self) -> bool:
        """Open the primary gate (Cancello Primario, WHERE=20)."""
        _LOGGER.info("Opening Primary Gate (addr: %s)", self.gate_addr)
        f_on = FRAME_DOOR_LOCK_ON.format(addr=self.gate_addr)
        f_off = FRAME_DOOR_LOCK_OFF.format(addr=self.gate_addr)
        r1 = await self.send_sip_command(f_on)
        await asyncio.sleep(0.3)
        r2 = await self.send_sip_command(f_off)
        return r1 and r2

    async def open_door(self) -> bool:
        """Open the secondary pedestrian door (Portoncino Secondario, WHERE=21)."""
        _LOGGER.info("Opening Secondary Portoncino (addr: %s)", self.door_addr)
        f_on = FRAME_DOOR_LOCK_ON.format(addr=self.door_addr)
        f_off = FRAME_DOOR_LOCK_OFF.format(addr=self.door_addr)
        r1 = await self.send_sip_command(f_on)
        await asyncio.sleep(0.3)
        r2 = await self.send_sip_command(f_off)
        return r1 and r2

    async def trigger_staircase_light(self) -> bool:
        """Trigger staircase / auxiliary light."""
        _LOGGER.info("Triggering staircase light")
        f = FRAME_STAIR_LIGHT.format(addr=self.gate_addr)
        return await self.send_sip_command(f)

    async def async_trigger_camera(self, duration: int = 15) -> bool:
        """Trigger outdoor camera streaming via SIP INVITE session."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_trigger_camera, duration)

    def _sync_trigger_camera(self, duration: int = 15) -> bool:
        """Connect to SIP TLS, perform REGISTER and send INVITE with SRTP to wake up camera."""
        if not self.cert_file or not self.key_file or not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            _LOGGER.error("Certificato o chiave SIP mancante per autoaccensione camera (%s, %s)", self.cert_file, self.key_file)
            return False

        target_uri = f"sip:MHT@{self.sip_domain}"
        call_id = str(uuid.uuid4())
        cseq = 1

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            ssl_sock = ctx.wrap_socket(s, server_hostname=self.sip_server)
            ssl_sock.connect((self.sip_server, self.sip_port))

            # 1. REGISTER
            branch = "z9hG4bK" + uuid.uuid4().hex[:12]
            tag = uuid.uuid4().hex[:8]
            reg_msg = (
                f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} REGISTER\r\n"
                f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                f"Expires: 300\r\n"
                f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            ssl_sock.sendall(reg_msg.encode())
            resp = ssl_sock.recv(4096).decode(errors="replace")
            if "401" in resp or "407" in resp:
                chal = _parse_digest_challenge(resp)
                auth_hdr = _compute_digest(
                    "REGISTER",
                    f"sip:{self.sip_domain}",
                    chal.get("realm", self.sip_domain),
                    chal.get("nonce", ""),
                    self.sip_user or "",
                    self.sip_pass or "",
                    qop=chal.get("qop"),
                    opaque=chal.get("opaque"),
                )
                cseq += 1
                branch = "z9hG4bK" + uuid.uuid4().hex[:12]
                reg_auth = (
                    f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                    f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq} REGISTER\r\n"
                    f"Authorization: {auth_hdr}\r\n"
                    f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                    f"Expires: 300\r\n"
                    f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                ssl_sock.sendall(reg_auth.encode())
                ssl_sock.recv(4096)

            # 2. INVITE with SRTP SDP to wake up camera
            cseq += 1
            branch = "z9hG4bK" + uuid.uuid4().hex[:12]
            tag = uuid.uuid4().hex[:8]
            crypto_key = "W190ZXN0X2tleV9mb3Jfc3J0cF9saW5waG9uZTF="
            sdp_body = (
                "v=0\r\n"
                f"o={self.sip_user} 123456 654321 IN IP4 192.168.1.100\r\n"
                "s=Talk\r\n"
                "c=IN IP4 192.168.1.100\r\n"
                "t=0 0\r\n"
                "m=audio 7078 RTP/SAVP 8 0 96\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:96 opus/48000/2\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{crypto_key}\r\n"
                "a=sendrecv\r\n"
                "m=video 9078 RTP/SAVP 97\r\n"
                "a=rtpmap:97 H264/90000\r\n"
                "a=fmtp:97 profile-level-id=42801F\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{crypto_key}\r\n"
                "a=recvonly\r\n"
                "a=DEVADDR:0\r\n"
                "a=CAMERASLIDING:1\r\n"
            )
            sdp_bytes = sdp_body.encode("utf-8")
            invite_msg = (
                f"INVITE {target_uri} SIP/2.0\r\n"
                f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={branch};rport\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                f"To: <{target_uri}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} INVITE\r\n"
                f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                f"Content-Type: application/sdp\r\n"
                f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                f"Content-Length: {len(sdp_bytes)}\r\n\r\n"
                f"{sdp_body}"
            )
            ssl_sock.sendall(invite_msg.encode())

            ssl_sock.settimeout(4.0)
            last_branch = branch
            start_t = time.time()
            camera_woken = False

            while time.time() - start_t < (duration + 5):
                try:
                    data = ssl_sock.recv(4096).decode(errors="replace")
                    if not data:
                        break
                    if "407 Proxy Authentication Required" in data or "401 Unauthorized" in data:
                        chal = _parse_digest_challenge(data)
                        auth_hdr = _compute_digest(
                            "INVITE",
                            target_uri,
                            chal.get("realm", self.sip_domain),
                            chal.get("nonce", ""),
                            self.sip_user or "",
                            self.sip_pass or "",
                            qop=chal.get("qop"),
                            opaque=chal.get("opaque"),
                        )
                        cseq += 1
                        last_branch = "z9hG4bK" + uuid.uuid4().hex[:12]
                        invite_auth = (
                            f"INVITE {target_uri} SIP/2.0\r\n"
                            f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={last_branch};rport\r\n"
                            f"Max-Forwards: 70\r\n"
                            f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                            f"To: <{target_uri}>\r\n"
                            f"Call-ID: {call_id}\r\n"
                            f"CSeq: {cseq} INVITE\r\n"
                            f"Proxy-Authorization: {auth_hdr}\r\n"
                            f"Contact: <sip:{self.sip_user}@192.168.1.100:5061;transport=tls>\r\n"
                            f"Content-Type: application/sdp\r\n"
                            f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                            f"Content-Length: {len(sdp_bytes)}\r\n\r\n"
                            f"{sdp_body}"
                        )
                        ssl_sock.sendall(invite_auth.encode())
                    elif "180 Ringing" in data or "200 OK" in data:
                        _LOGGER.info("Telecamera svegliata con successo via SIP INVITE! (180 Ringing)")
                        camera_woken = True
                        time.sleep(duration)
                        cancel_msg = (
                            f"CANCEL {target_uri} SIP/2.0\r\n"
                            f"Via: SIP/2.0/TLS 192.168.1.100:5061;branch={last_branch};rport\r\n"
                            f"Max-Forwards: 70\r\n"
                            f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={tag}\r\n"
                            f"To: <{target_uri}>\r\n"
                            f"Call-ID: {call_id}\r\n"
                            f"CSeq: {cseq} CANCEL\r\n"
                            f"User-Agent: DoorEntryTouch/1.9.2\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        )
                        ssl_sock.sendall(cancel_msg.encode())
                        break
                except socket.timeout:
                    break

            ssl_sock.close()
            return camera_woken
        except Exception as err:
            _LOGGER.error("Errore durante attivazione sessione SIP camera: %s", err)
            return False

    async def start_monitoring(self) -> None:
        """Start background tasks to monitor doorbell events."""
        if self._running:
            return
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._sip_listener_task = asyncio.create_task(self._sip_listener_loop())

    async def stop_monitoring(self) -> None:
        """Stop background monitor tasks."""
        self._running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        if self._sip_listener_task and not self._sip_listener_task.done():
            self._sip_listener_task.cancel()
            try:
                await self._sip_listener_task
            except asyncio.CancelledError:
                pass

    async def _authenticate_session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resp_str: str) -> bool:
        """Perform HMAC-SHA256 authentication on OpenWebNet port 20000."""
        _LOGGER.info("Handshake sessione monitor: ricevuto '%s'", resp_str)
        if resp_str == OWN_ACK:
            _LOGGER.info("Sessione monitor aperta senza autenticazione necessaria (ACK diretto).")
            return True

        if "*98*2##" in resp_str:
            if not self.password:
                _LOGGER.error("Il citofono richiede autenticazione HMAC-SHA256 (*98*2##) ma nessuna password è configurata!")
                return False

            _LOGGER.info("Citofono richiede autenticazione HMAC-SHA256 (*98*2##). Invio ACK...")
            writer.write(OWN_ACK.encode())
            await writer.drain()

            ra_resp = await reader.read(256)
            ra_str = ra_resp.decode("latin1", errors="replace")
            _LOGGER.info("Ricevuto nonce RA dal citofono: %s", ra_str)

            if ra_str.startswith("*#") and ra_str.endswith("##"):
                ra_wire = ra_str[2:-2]
                rb_wire, hmac_wire = _calc_hmac_sha256_response(ra_wire, self.password)
                client_resp = f"*#{rb_wire}*{hmac_wire}##"
                _LOGGER.info("Invio risposta HMAC calcolata al citofono...")
                writer.write(client_resp.encode())
                await writer.drain()

                auth_result = await reader.read(256)
                res_str = auth_result.decode("latin1", errors="replace")
                _LOGGER.info("Esito autenticazione dal citofono: %s", res_str)
                if res_str.startswith("*#") and res_str.endswith("##") and res_str != OWN_NACK:
                    writer.write(OWN_ACK.encode())
                    await writer.drain()
                    _LOGGER.info("✅ Autenticazione monitor OpenWebNet RIUSCITA!")
                    return True
                else:
                    _LOGGER.error("❌ Autenticazione monitor FALLITA (ricevuto %s). Verificare la password OpenWebNet!", res_str)
        else:
            _LOGGER.warning("Risposta inattesa alla richiesta monitor: %s", resp_str)
        return False

    async def _monitor_loop(self) -> None:
        """Maintain persistent connection to monitor bus events on port 20000."""
        while self._running:
            try:
                _LOGGER.info("Connessione in corso a %s:%s per ascolto eventi bus citofono...", self.host, self.port)
                reader, writer = await asyncio.open_connection(self.host, self.port)
                init_ack = await reader.read(100)
                init_ack_str = init_ack.decode("latin1", errors="replace")
                _LOGGER.info("Connesso al citofono (ACK iniziale: %s). Richiesta sessione monitor (*99*1##)...", init_ack_str)

                writer.write(OWN_MONITOR_SESSION.encode())
                await writer.drain()
                resp = await reader.read(100)
                resp_str = resp.decode("latin1", errors="replace")

                auth_ok = await self._authenticate_session(reader, writer, resp_str)
                if not auth_ok:
                    _LOGGER.warning("Autenticazione sessione monitor non riuscita. Nuovo tentativo tra 15s...")
                    writer.close()
                    await writer.wait_closed()
                    await asyncio.sleep(15)
                    continue

                _LOGGER.info("🎉 Connesso alla sessione monitor! IN ASCOLTO DI TUTTI I FRAME DEL BUS CITOFONO...")
                buffer = ""
                while self._running:
                    chunk = await reader.read(256)
                    if not chunk:
                        _LOGGER.warning("Connessione monitor chiusa dal citofono.")
                        break
                    buffer += chunk.decode("latin1", errors="replace")
                    while "##" in buffer:
                        idx = buffer.find("##") + 2
                        frame = buffer[:idx]
                        buffer = buffer[idx:]
                        self._process_monitor_frame(frame)

                writer.close()
                await writer.wait_closed()
            except asyncio.CancelledError:
                break
            except Exception as err:
                _LOGGER.warning("Connessione monitor persa (%s). Riconnessione tra 10s...", err)
                await asyncio.sleep(10)

    def _process_monitor_frame(self, frame: str) -> None:
        """Process incoming OpenWebNet frame from monitor session."""
        _LOGGER.info("📩 [BUS CITOFONO FRAME]: %s", frame)

        is_call_start = False
        is_call_end = False

        if (
            OWN_CALL_PATTERN in frame
            or "*8*1#" in frame
            or "*8*20#" in frame
            or "*8*19#" in frame
            or "*8*91##" in frame
            or "*8*1*" in frame
            or "*8*2*" in frame
            or "*7*1#" in frame
        ):
            is_call_start = True
        elif OWN_CALL_END_PATTERN in frame or "*8*92##" in frame or "*8*0#" in frame or "*8*0*" in frame:
            is_call_end = True
        elif frame.startswith("*8*") and frame.endswith("##"):
            # Qualsiasi frame videocitofonico WHO=8
            _LOGGER.info("Frame videocitofonia generico WHO=8 rilevato: %s", frame)
            is_call_start = True

        if is_call_start:
            _LOGGER.info("🔔🔔🔔 CAMPANELLO ATTIVO! Rilevata chiamata citofonica (frame: %s) 🔔🔔🔔", frame)
            self._is_call_active = True
            self._notify_event("doorbell", True)
            asyncio.create_task(self._auto_reset_doorbell(25))
        elif is_call_end:
            _LOGGER.info("🔕 Chiamata citofono terminata (frame: %s)", frame)
            self._is_call_active = False
            self._notify_event("doorbell", False)

    async def _auto_reset_doorbell(self, timeout: int = 25) -> None:
        """Auto reset doorbell state after timeout if no end frame is received."""
        await asyncio.sleep(timeout)
        if self._is_call_active:
            _LOGGER.info("Auto-reset stato campanello dopo %ds di timeout", timeout)
            self._is_call_active = False
            self._notify_event("doorbell", False)

    async def _sip_listener_loop(self) -> None:
        """Maintain persistent SIP TLS connection to receive incoming calls (doorbell rings)."""
        if not self.sip_server or not self.sip_user or not self.cert_file or not self.key_file:
            _LOGGER.debug("SIP listener non avviato: credenziali o certificati SIP mancanti.")
            return

        _LOGGER.warning("🚀 Avvio monitor chiamate SIP BTicino su %s:%d (account: %s)", self.sip_server, self.sip_port, self.sip_user)

        while self._running:
            writer: asyncio.StreamWriter | None = None
            try:
                _LOGGER.info("Connessione SIP TLS a %s:%d...", self.sip_server, self.sip_port)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

                reader, writer = await asyncio.open_connection(self.sip_server, self.sip_port, ssl=ctx)

                call_id = f"ha-sip-{secrets.token_hex(8)}"
                from_tag = f"tag-{secrets.token_hex(4)}"
                cseq = 1

                reg_msg = (
                    f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TLS 127.0.0.1:{self.sip_port};branch=z9hG4bK-{secrets.token_hex(4)}\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={from_tag}\r\n"
                    f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq} REGISTER\r\n"
                    f"Contact: <sip:{self.sip_user}@127.0.0.1:{self.sip_port};transport=tls>\r\n"
                    f"Expires: 300\r\n"
                    f"User-Agent: BTicino-HOMETOUCH-HA/1.0\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                writer.write(reg_msg.encode())
                await writer.drain()

                resp = (await reader.read(2048)).decode("latin1", errors="replace")
                if "401 Unauthorized" in resp and self.sip_pass:
                    chal = _parse_digest_challenge(resp)
                    realm = chal.get("realm", self.sip_domain or "")
                    nonce = chal.get("nonce", "")
                    cseq += 1
                    auth_digest = _compute_digest(
                        "REGISTER",
                        f"sip:{self.sip_domain}",
                        realm,
                        nonce,
                        self.sip_user,
                        self.sip_pass,
                        qop=chal.get("qop"),
                        opaque=chal.get("opaque"),
                    )
                    auth_reg = (
                        f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                        f"Via: SIP/2.0/TLS 127.0.0.1:{self.sip_port};branch=z9hG4bK-{secrets.token_hex(4)}\r\n"
                        f"Max-Forwards: 70\r\n"
                        f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={from_tag}\r\n"
                        f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                        f"Call-ID: {call_id}\r\n"
                        f"CSeq: {cseq} REGISTER\r\n"
                        f"Contact: <sip:{self.sip_user}@127.0.0.1:{self.sip_port};transport=tls>\r\n"
                        f"Authorization: {auth_digest}\r\n"
                        f"Expires: 300\r\n"
                        f"User-Agent: BTicino-HOMETOUCH-HA/1.0\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    )
                    writer.write(auth_reg.encode())
                    await writer.drain()
                    resp = (await reader.read(2048)).decode("latin1", errors="replace")

                if "200 " in resp or "200 OK" in resp or "successful" in resp.lower():
                    _LOGGER.warning("🎉 Connessione SIP stabilita con successo! In ascolto delle chiamate dal campanello...")
                else:
                    _LOGGER.warning("Registrazione SIP non riuscita: %s", resp[:150])
                    writer.close()
                    await writer.wait_closed()
                    await asyncio.sleep(20)
                    continue

                last_keepalive = time.time()
                buffer = ""

                while self._running:
                    now = time.time()
                    if now - last_keepalive > 120:
                        cseq += 1
                        re_reg = (
                            f"REGISTER sip:{self.sip_domain} SIP/2.0\r\n"
                            f"Via: SIP/2.0/TLS 127.0.0.1:{self.sip_port};branch=z9hG4bK-{secrets.token_hex(4)}\r\n"
                            f"Max-Forwards: 70\r\n"
                            f"From: <sip:{self.sip_user}@{self.sip_domain}>;tag={from_tag}\r\n"
                            f"To: <sip:{self.sip_user}@{self.sip_domain}>\r\n"
                            f"Call-ID: {call_id}\r\n"
                            f"CSeq: {cseq} REGISTER\r\n"
                            f"Contact: <sip:{self.sip_user}@127.0.0.1:{self.sip_port};transport=tls>\r\n"
                            f"Expires: 300\r\n"
                            f"User-Agent: BTicino-HOMETOUCH-HA/1.0\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        )
                        writer.write(re_reg.encode())
                        await writer.drain()
                        last_keepalive = now

                    try:
                        chunk = await asyncio.wait_for(reader.read(2048), timeout=30.0)
                        if not chunk:
                            _LOGGER.warning("Connessione SIP chiusa dal server remoto.")
                            break
                        buffer += chunk.decode("latin1", errors="replace")
                        self._process_sip_incoming(buffer, writer)
                        buffer = ""
                    except asyncio.TimeoutError:
                        continue

                if writer:
                    writer.close()
                    await writer.wait_closed()
            except asyncio.CancelledError:
                break
            except Exception as err:
                _LOGGER.warning("Errore connessione SIP listener (%s). Riconnessione tra 15s...", err)
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                await asyncio.sleep(15)

    def _process_sip_incoming(self, data: str, writer: asyncio.StreamWriter) -> None:
        """Process incoming SIP messages from server."""
        _LOGGER.debug("Ricevuto messaggio SIP: %s", data[:200])

        if "INVITE " in data:
            _LOGGER.warning("🔔🔔🔔 CAMPANELLO ATTIVO! Rilevata chiamata citofonica in arrivo! 🔔🔔🔔")
            self._is_call_active = True
            self._notify_event("doorbell", True)

            via = ""
            from_hdr = ""
            to_hdr = ""
            call_id = ""
            cseq = ""
            for line in data.splitlines():
                ll = line.lower()
                if ll.startswith("via:"):
                    via = line[4:].strip()
                elif ll.startswith("from:"):
                    from_hdr = line[5:].strip()
                elif ll.startswith("to:"):
                    to_hdr = line[3:].strip()
                elif ll.startswith("call-id:"):
                    call_id = line[8:].strip()
                elif ll.startswith("cseq:"):
                    cseq = line[5:].strip()

            if via and from_hdr and to_hdr and call_id and cseq:
                ringing_resp = (
                    f"SIP/2.0 180 Ringing\r\n"
                    f"Via: {via}\r\n"
                    f"From: {from_hdr}\r\n"
                    f"To: {to_hdr};tag=ha-{secrets.token_hex(4)}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                try:
                    writer.write(ringing_resp.encode())
                    asyncio.create_task(writer.drain())
                except Exception as err:
                    _LOGGER.warning("Errore invio 180 Ringing: %s", err)

            asyncio.create_task(self._auto_reset_doorbell(30))

        elif "CANCEL " in data or "BYE " in data:
            _LOGGER.warning("🔕 Chiamata citofonica terminata.")
            self._is_call_active = False
            self._notify_event("doorbell", False)
            via = ""
            from_hdr = ""
            to_hdr = ""
            call_id = ""
            cseq = ""
            for line in data.splitlines():
                ll = line.lower()
                if ll.startswith("via:"):
                    via = line[4:].strip()
                elif ll.startswith("from:"):
                    from_hdr = line[5:].strip()
                elif ll.startswith("to:"):
                    to_hdr = line[3:].strip()
                elif ll.startswith("call-id:"):
                    call_id = line[8:].strip()
                elif ll.startswith("cseq:"):
                    cseq = line[5:].strip()
            if via and call_id and cseq:
                ok_resp = (
                    f"SIP/2.0 200 OK\r\n"
                    f"Via: {via}\r\n"
                    f"From: {from_hdr}\r\n"
                    f"To: {to_hdr}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                try:
                    writer.write(ok_resp.encode())
                    asyncio.create_task(writer.drain())
                except Exception:
                    pass

