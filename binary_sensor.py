"""Binary sensor platform for BTicino HOMETOUCH integration."""

from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
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
    """Set up the BTicino HOMETOUCH binary sensor platform."""
    client: HometouchClient = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([HometouchDoorbellSensor(client, entry)], True)


class HometouchDoorbellSensor(BinarySensorEntity):
    """Binary sensor for detecting intercom doorbell ring / call in progress."""

    _attr_has_entity_name = True
    _attr_translation_key = "doorbell"
    _attr_name = "Campanello Chiamata"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY
    _attr_icon = "mdi:bell-ring"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the doorbell sensor."""
        self._client = client
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_doorbell"
        self._attr_is_on = False
        self._unsubscribe_listener = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to Home Assistant."""
        self._unsubscribe_listener = self._client.register_listener(self._handle_event)
        self._attr_is_on = self._client.is_call_active

    async def async_will_remove_from_hass(self) -> None:
        """Clean up listeners when removed."""
        if self._unsubscribe_listener:
            self._unsubscribe_listener()

    @callback
    def _handle_event(self, event_type: str, state: bool) -> None:
        """Handle incoming intercom event."""
        if event_type == "doorbell":
            self._attr_is_on = state
            self.async_write_ha_state()
