"""The BTicino HOMETOUCH integration."""

from __future__ import annotations

import logging
import os
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .client import HometouchClient
from .const import (
    CONF_CERT_PATH,
    CONF_DOOR_ADDR,
    CONF_GATE_ADDR,
    CONF_GATEWAY_ID,
    CONF_HOST,
    CONF_KEY_PATH,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PSW_OPEN,
    CONF_SIP_ACCOUNT,
    CONF_SIP_PASSWORD,
    CONF_SIP_SERVER,
    CONF_USERNAME,
    DEFAULT_DOOR_ADDR,
    DEFAULT_GATE_ADDR,
    DEFAULT_PORT,
    DEFAULT_SIP_PORT,
    DEFAULT_SIP_SERVER,
    DOMAIN,
    PLATFORMS,
)
from .eliot import EliotCloudClient

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the BTicino HOMETOUCH component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up BTicino HOMETOUCH from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    host = entry.data[CONF_HOST]
    port = entry.data.get(CONF_PORT, DEFAULT_PORT)
    psw_open = entry.data.get(CONF_PSW_OPEN)
    gw_id = entry.data.get(CONF_GATEWAY_ID, "")
    sip_account = entry.data.get(CONF_SIP_ACCOUNT)
    sip_pass = entry.data.get(CONF_SIP_PASSWORD)
    sip_server = entry.data.get(CONF_SIP_SERVER, DEFAULT_SIP_SERVER)
    cert_file = entry.data.get(CONF_CERT_PATH)
    key_file = entry.data.get(CONF_KEY_PATH)

    gate_addr = entry.options.get(CONF_GATE_ADDR, entry.data.get(CONF_GATE_ADDR, DEFAULT_GATE_ADDR))
    door_addr = entry.options.get(CONF_DOOR_ADDR, entry.data.get(CONF_DOOR_ADDR, DEFAULT_DOOR_ADDR))

    # Check if certificate exists, re-enroll if missing
    if not cert_file or not key_file or not os.path.exists(cert_file) or not os.path.exists(key_file):
        username = entry.data.get(CONF_USERNAME)
        password = entry.data.get(CONF_PASSWORD)
        if username and password and sip_account:
            try:
                _LOGGER.info("Client certificate not found, enrolling with Eliot Cloud...")
                eliot = EliotCloudClient(username, password)
                await eliot.async_sign_in()
                storage_dir = hass.config.path(".storage", DOMAIN, gw_id or "default")
                cert_file, key_file, _ = await eliot.async_enroll_certificate(sip_account, storage_dir)
            except Exception as err:
                _LOGGER.warning("Could not re-enroll certificate: %s", err)

    sip_domain = f"{gw_id}.bs.iotleg.com" if gw_id else None

    _LOGGER.info("Setting up BTicino HOMETOUCH integration for host: %s (Gateway: %s)", host, gw_id)

    client = HometouchClient(
        host=host,
        port=port,
        password=psw_open,
        sip_user=sip_account,
        sip_pass=sip_pass,
        sip_domain=sip_domain,
        sip_server=sip_server,
        sip_port=DEFAULT_SIP_PORT,
        cert_file=cert_file,
        key_file=key_file,
        gate_addr=str(gate_addr),
        door_addr=str(door_addr),
    )

    # Start background event monitoring for doorbell rings on local LAN
    await client.start_monitoring()

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
    }

    # Register platforms (lock, button, binary_sensor)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        data = hass.data[DOMAIN].pop(entry.entry_id, {})
        client: HometouchClient | None = data.get("client")
        if client:
            await client.stop_monitoring()

    return unload_ok


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)
