"""Lock platform for BTicino HOMETOUCH integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
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
    """Set up the BTicino HOMETOUCH lock platform."""
    client: HometouchClient = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities(
        [
            HometouchGateLock(client, entry),
            HometouchDoorLock(client, entry),
        ],
        True,
    )


class HometouchBaseLock(LockEntity):
    """Base class for Hometouch locks."""

    _attr_has_entity_name = True

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize base lock."""
        self._client = client
        self._entry = entry
        self._attr_is_locked = True
        self._reset_task: asyncio.Task | None = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )

    @property
    def is_locked(self) -> bool:
        """Return true if lock is locked."""
        return self._attr_is_locked

    async def async_lock(self, **kwargs: Any) -> None:
        """Visual lock state reset."""
        self._attr_is_locked = True
        self.async_write_ha_state()

    async def _auto_relock(self) -> None:
        """Automatically reset the lock state to locked after a pulse delay."""
        await asyncio.sleep(5)
        self._attr_is_locked = True
        self.async_write_ha_state()


class HometouchGateLock(HometouchBaseLock):
    """Primary Gate lock (Cancello)."""

    _attr_translation_key = "gate_lock"
    _attr_name = "Cancello"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize gate lock."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_gate_lock"

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the primary gate."""
        _LOGGER.info("Unlocking Cancello via Hometouch SIP")
        success = await self._client.open_gate()
        if success:
            self._attr_is_locked = False
            self.async_write_ha_state()
            if self._reset_task and not self._reset_task.done():
                self._reset_task.cancel()
            self._reset_task = asyncio.create_task(self._auto_relock())
        else:
            _LOGGER.error("Failed to unlock Cancello")


class HometouchDoorLock(HometouchBaseLock):
    """Secondary Pedestrian Door lock (Portoncino)."""

    _attr_translation_key = "door_lock"
    _attr_name = "Portoncino"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize door lock."""
        super().__init__(client, entry)
        self._attr_unique_id = f"{entry.entry_id}_door_lock"

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the secondary portoncino."""
        _LOGGER.info("Unlocking Portoncino via Hometouch SIP")
        success = await self._client.open_door()
        if success:
            self._attr_is_locked = False
            self.async_write_ha_state()
            if self._reset_task and not self._reset_task.done():
                self._reset_task.cancel()
            self._reset_task = asyncio.create_task(self._auto_relock())
        else:
            _LOGGER.error("Failed to unlock Portoncino")
