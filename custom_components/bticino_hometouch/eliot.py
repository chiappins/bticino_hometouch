"""Legrand Eliot Cloud Client for BTicino HOMETOUCH."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import ssl
import subprocess
import urllib.request
import urllib.error
import zipfile
from typing import Any

_LOGGER = logging.getLogger(__name__)

ELIOT_SERVERS = [
    "https://stable-eliot-mule-balancer-2146709889.eu-west-1.elb.amazonaws.com:8080",
    "https://stable-eliot-mule-balancer-2146709889.eu-west-1.elb.amazonaws.com",
    "https://www.myhomeweb.com:8080",
    "https://www.myhomeweb.com",
]

PRJ_NAME = "MHT"
APP_VERSION = "1.9.2"


class EliotCloudClient:
    """Client to interact with Legrand Eliot Cloud API for BTicino HOMETOUCH."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.auth_token: str | None = None
        self.base_url: str | None = None
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _sync_request(self, path: str, method: str = "GET", data: dict | None = None) -> Any:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "prj_name": PRJ_NAME,
        }
        if self.auth_token:
            headers["auth_token"] = self.auth_token

        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        servers = [self.base_url] if self.base_url else ELIOT_SERVERS

        last_error: Exception | None = None
        for srv in servers:
            if not srv:
                continue
            url = f"{srv}{path}"
            req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=12, context=self.ssl_ctx) as resp:
                    new_token = resp.headers.get("auth_token") or resp.headers.get("Auth_Token")
                    if new_token:
                        self.auth_token = new_token
                    
                    raw_bytes = resp.read()
                    if raw_bytes.startswith(b"\x1f\x8b"):
                        import gzip
                        try:
                            raw_bytes = gzip.decompress(raw_bytes)
                        except Exception:
                            pass

                    self.base_url = srv
                    try:
                        res_body = raw_bytes.decode("utf-8")
                        if res_body:
                            try:
                                return json.loads(res_body)
                            except json.JSONDecodeError:
                                return res_body
                        return {}
                    except UnicodeDecodeError:
                        return raw_bytes
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                _LOGGER.error("HTTP %s from %s: %s", e.code, url, err_body)
                last_error = e
                if e.code in (401, 403):
                    raise RuntimeError(f"Credenziali Eliot non valide ({e.code}): {err_body}") from e
            except Exception as e:
                last_error = e

        raise RuntimeError(f"Impossibile raggiungere server Eliot: {last_error}")

    async def async_sign_in(self) -> dict[str, Any]:
        """Async login to Eliot cloud."""
        payload = {
            "username": self.username,
            "pwd": self.password,
            "appVersion": APP_VERSION,
            "registrationId": "",
        }
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, self._sync_request, "/eliot/users/sign_in", "POST", payload)
        if isinstance(res, dict):
            for k in ("auth_token", "token", "Token", "authToken"):
                if k in res:
                    self.auth_token = res[k]
                    break
        return res if isinstance(res, dict) else {}

    async def async_get_plants(self) -> list[dict[str, Any]]:
        """Async get list of plants."""
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, self._sync_request, "/eliot/plants", "GET", None)
        if isinstance(res, list):
            return res
        if isinstance(res, dict):
            return res.get("plants", [res])
        return []

    async def async_get_gateway_info(self, plant_id: str, gateway_id: str | None = None) -> dict[str, Any]:
        """Async get gateway details including PswOpen."""
        path = f"/eliot/plants/{plant_id}/gateway/{gateway_id}" if gateway_id else f"/eliot/plants/{plant_id}/gateway"
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, self._sync_request, path, "GET", None)
        return res if isinstance(res, dict) else {}

    async def async_get_sip_credentials(self, plant_id: str, gateway_id: str | None = None) -> dict[str, Any]:
        """Async get SIP credentials."""
        path = f"/eliot/sip/users/plants/{plant_id}/gateway/{gateway_id}" if gateway_id else f"/eliot/sip/users/plants/{plant_id}"
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, self._sync_request, path, "GET", None)
        return res if isinstance(res, dict) else {}

    def _sync_enroll_cert(self, sip_account: str, storage_dir: str) -> tuple[str, str, str]:
        """Generate key/CSR and obtain signed client certificate from Eliot."""
        os.makedirs(storage_dir, exist_ok=True)
        key_file = os.path.join(storage_dir, "client.key")
        cert_file = os.path.join(storage_dir, "client.crt")
        ca_file = os.path.join(storage_dir, "ca.crt")
        csr_file = os.path.join(storage_dir, "client.csr")

        # Check if already present
        if os.path.exists(key_file) and os.path.exists(cert_file):
            _LOGGER.info("Using existing SIP client certificate at %s", cert_file)
            return cert_file, key_file, ca_file

        _LOGGER.info("Generating new RSA 2048-bit key and CSR for %s...", sip_account)
        subj = f"/C=IT/ST=Italy/L=Varese/O=Bticino spa/OU=DSI-PQS/CN={sip_account}"
        subprocess.run(["openssl", "genrsa", "-out", key_file, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-key", key_file, "-out", csr_file, "-subj", subj], check=True, capture_output=True)

        with open(csr_file, "r") as f:
            csr_pem = f.read()

        payload = {
            "CommonName": sip_account,
            "CSR": csr_pem,
        }

        _LOGGER.info("Requesting signed certificate from Eliot cloud...")
        res = self._sync_request("/eliot/users/cert/signcert", method="POST", data=payload)

        # Handle zip or raw response
        if isinstance(res, bytes):
            try:
                with zipfile.ZipFile(io.BytesIO(res)) as zf:
                    for name in zf.namelist():
                        if "ca-chain" in name.lower():
                            with open(ca_file, "wb") as out_ca:
                                out_ca.write(zf.read(name))
                        elif name.endswith(".cert.pem") or name.endswith(".crt"):
                            with open(cert_file, "wb") as out_cert:
                                out_cert.write(zf.read(name))
            except zipfile.BadZipFile:
                # Raw cert DER or PEM
                with open(cert_file, "wb") as out_cert:
                    out_cert.write(res)
        elif isinstance(res, dict):
            for k, v in res.items():
                if "cert" in k.lower() or "crt" in k.lower() or "-----BEGIN CERTIFICATE" in str(v):
                    with open(cert_file, "w") as out_cert:
                        out_cert.write(str(v))
                    break

        if not os.path.exists(cert_file):
            raise RuntimeError("Impossibile salvare il certificato client firmato da Eliot")

        _LOGGER.info("Successfully enrolled SIP client certificate at %s", cert_file)
        return cert_file, key_file, ca_file

    async def async_enroll_certificate(self, sip_account: str, storage_dir: str) -> tuple[str, str, str]:
        """Async wrapper for certificate enrollment."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_enroll_cert, sip_account, storage_dir)
