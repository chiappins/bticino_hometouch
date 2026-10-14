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

    entities: list[BinarySensorEntity] = [
        HometouchDoorbellSensor(client, entry),
        HometouchGateDoorbellSensor(client, entry),
        HometouchDoorDoorbellSensor(client, entry),
    ]

    async_add_entities(entities, True)


class HometouchBaseDoorbellSensor(BinarySensorEntity):
    """Base binary sensor for BTicino doorbell calls."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY
    _attr_icon = "mdi:bell-ring"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize base doorbell sensor."""
        self._client = client
        self._entry = entry
        self._attr_is_on = False
        self._unsubscribe_listener = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )

    async def async_will_remove_from_hass(self) -> None:
        """Clean up listeners when removed."""
        if self._unsubscribe_listener:
            self._unsubscribe_listener()


class HometouchDoorbellSensor(HometouchBaseDoorbellSensor):
    """Binary sensor for detecting any intercom doorbell call (Generale)."""

    _attr_translation_key = "doorbell"
    _attr_name = "Campanello Chiamata"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize general doorbell sensor."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_doorbell"

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to Home Assistant."""
        self._unsubscribe_listener = self._client.register_listener(self._handle_event)
        self._attr_is_on = self._client.is_call_active

    @callback
    def _handle_event(self, event_type: str, state: bool) -> None:
        """Handle incoming intercom event."""
        if event_type == "doorbell":
            self._attr_is_on = state
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "ultimo_varco": self._client.last_call_source,
            "indirizzo_bus": self._client.last_call_address,
            "ultimo_frame": self._client.last_call_frame,
        }


class HometouchGateDoorbellSensor(HometouchBaseDoorbellSensor):
    """Binary sensor for Cancelletto (addr 20)."""

    _attr_translation_key = "doorbell_gate"
    _attr_name = "Campanello Cancelletto"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize gate doorbell sensor."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_doorbell_gate"

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to Home Assistant."""
        self._unsubscribe_listener = self._client.register_listener(self._handle_event)
        self._attr_is_on = self._client.is_gate_call_active

    @callback
    def _handle_event(self, event_type: str, state: bool) -> None:
        """Handle incoming intercom event."""
        if event_type == "doorbell_gate":
            self._attr_is_on = state
            self.async_write_ha_state()


class HometouchDoorDoorbellSensor(HometouchBaseDoorbellSensor):
    """Binary sensor for Portoncino (addr 21)."""

    _attr_translation_key = "doorbell_door"
    _attr_name = "Campanello Portoncino"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize door doorbell sensor."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_doorbell_door"

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to Home Assistant."""
        self._unsubscribe_listener = self._client.register_listener(self._handle_event)
        self._attr_is_on = self._client.is_door_call_active

    @callback
    def _handle_event(self, event_type: str, state: bool) -> None:
        """Handle incoming intercom event."""
        if event_type == "doorbell_door":
            self._attr_is_on = state
            self.async_write_ha_state()
