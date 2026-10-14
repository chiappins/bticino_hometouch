"""Button platform for BTicino HOMETOUCH integration."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import HometouchClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the BTicino HOMETOUCH button platform."""
    client: HometouchClient = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities(
        [
            HometouchGateButton(client, entry),
            HometouchDoorButton(client, entry),
            HometouchStairLightButton(client, entry),
            HometouchCameraButton(client, entry),
            HometouchSecondaryCameraButton(client, entry),
        ],
        True,
    )


class HometouchBaseButton(ButtonEntity):
    """Base class for Hometouch buttons."""

    _attr_has_entity_name = True

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the button."""
        self._client = client
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )


class HometouchGateButton(HometouchBaseButton):
    """Button to open the gate (Cancello)."""

    _attr_translation_key = "open_gate"
    _attr_name = "Apri Cancello"
    _attr_icon = "mdi:gate"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the gate button."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_open_gate"

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Opening gate via Hometouch")
        await self._client.open_gate()


class HometouchDoorButton(HometouchBaseButton):
    """Button to pulse the door lock (Portoncino)."""

    _attr_translation_key = "open_door"
    _attr_name = "Apri Portoncino"
    _attr_icon = "mdi:door-open"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the door button."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_open_door"

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Opening door via Hometouch")
        await self._client.open_door()


class HometouchStairLightButton(HometouchBaseButton):
    """Button to trigger staircase / auxiliary light."""

    _attr_translation_key = "stair_light"
    _attr_name = "Luce Scale"
    _attr_icon = "mdi:lightbulb-outline"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the staircase light button."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_stair_light"

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Triggering staircase light via Hometouch")
        await self._client.trigger_staircase_light()


class HometouchCameraButton(HometouchBaseButton):
    """Button to wake up primary outdoor camera via SIP session."""

    _attr_translation_key = "trigger_camera"
    _attr_name = "Accendi Telecamera Cancello (SIP)"
    _attr_icon = "mdi:camera-wireless"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the camera trigger button."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_trigger_camera"

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Waking up primary outdoor camera (Cancello PE 0, DEVADDR 20) via SIP session")
        await self._client.async_trigger_camera(devaddr="20")


class HometouchSecondaryCameraButton(HometouchBaseButton):
    """Button to wake up secondary outdoor camera via SIP session."""

    _attr_translation_key = "trigger_camera_secondary"
    _attr_name = "Accendi Telecamera Portoncino (SIP)"
    _attr_icon = "mdi:camera-wireless-outline"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the secondary camera trigger button."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_trigger_camera_secondary"

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Waking up secondary outdoor camera (Portoncino PE 1, DEVADDR 21) via SIP session")
        await self._client.async_trigger_camera(devaddr="21")

