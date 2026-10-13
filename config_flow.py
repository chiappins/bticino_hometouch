"""Config flow for BTicino HOMETOUCH integration."""

from __future__ import annotations

import logging
import os
from typing import Any
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

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
)
from .eliot import EliotCloudClient

_LOGGER = logging.getLogger(__name__)


class HometouchConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for BTicino HOMETOUCH."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle initial step: user inputs IP, Eliot username, and Eliot password."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            username = user_input[CONF_USERNAME].strip()
            password = user_input[CONF_PASSWORD].strip()
            door_addr = user_input.get(CONF_DOOR_ADDR, DEFAULT_DOOR_ADDR).strip()
            gate_addr = user_input.get(CONF_GATE_ADDR, DEFAULT_GATE_ADDR).strip()

            await self.async_set_unique_id(f"bticino_hometouch_{host}")
            self._abort_if_unique_id_configured()

            # Execute Eliot Cloud enrollment
            try:
                eliot_client = EliotCloudClient(username=username, password=password)
                _LOGGER.info("Autenticazione Cloud Legrand Eliot per %s...", username)
                await eliot_client.async_sign_in()

                plants = await eliot_client.async_get_plants()
                if not plants:
                    raise RuntimeError("Nessun impianto BTicino / Eliot associato a questo account")

                plant_id = str(plants[0].get("id") or plants[0].get("PlantId") or plants[0].get("plantId"))
                gw_info = await eliot_client.async_get_gateway_info(plant_id)
                gw_id = None
                psw_open = ""

                gw_list = gw_info if isinstance(gw_info, list) else [gw_info]
                for item in gw_list:
                    if isinstance(item, dict):
                        if item.get("PswOpen"):
                            psw_open = str(item["PswOpen"])
                        if item.get("GatewayId"):
                            gw_id = str(item["GatewayId"])

                sip_info = await eliot_client.async_get_sip_credentials(plant_id, gw_id)
                sip_account = ""
                sip_pass = ""

                sip_list = sip_info if isinstance(sip_info, list) else [sip_info]
                for s in sip_list:
                    if isinstance(s, dict) and s.get("SipAccount"):
                        sip_account = s["SipAccount"]
                        sip_pass = s.get("SipPassword", "")
                        break

                if not sip_account:
                    raise RuntimeError("Credenziali SIP non trovate sull'account Eliot")

                # Storage path for certificates
                storage_dir = self.hass.config.path(".storage", DOMAIN, gw_id or "default")
                cert_file, key_file, _ = await eliot_client.async_enroll_certificate(sip_account, storage_dir)

                return self.async_create_entry(
                    title=f"BTicino HOMETOUCH ({host})",
                    data={
                        CONF_HOST: host,
                        CONF_PORT: DEFAULT_PORT,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                        CONF_PSW_OPEN: psw_open,
                        CONF_GATEWAY_ID: gw_id or "",
                        CONF_SIP_ACCOUNT: sip_account,
                        CONF_SIP_PASSWORD: sip_pass,
                        CONF_SIP_SERVER: DEFAULT_SIP_SERVER,
                        CONF_CERT_PATH: cert_file,
                        CONF_KEY_PATH: key_file,
                        CONF_GATE_ADDR: gate_addr,
                        CONF_DOOR_ADDR: door_addr,
                    },
                )
            except Exception as err:
                _LOGGER.error("Errore durante configurazione BTicino HOMETOUCH: %s", err)
                errors["base"] = "cannot_connect"

        data_schema = vol.Schema(
            {
                vol.Required(CONF_HOST, default="192.168.1.103"): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_GATE_ADDR, default=DEFAULT_GATE_ADDR): str,
                vol.Optional(CONF_DOOR_ADDR, default=DEFAULT_DOOR_ADDR): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return HometouchOptionsFlowHandler(config_entry)


class HometouchOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options for BTicino HOMETOUCH."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data = self.config_entry.data
        options = self.config_entry.options

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_GATE_ADDR,
                        default=options.get(CONF_GATE_ADDR, data.get(CONF_GATE_ADDR, DEFAULT_GATE_ADDR)),
                    ): str,
                    vol.Optional(
                        CONF_DOOR_ADDR,
                        default=options.get(CONF_DOOR_ADDR, data.get(CONF_DOOR_ADDR, DEFAULT_DOOR_ADDR)),
                    ): str,
                }
            ),
        )
