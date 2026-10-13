"""Camera platform for BTicino HOMETOUCH integration."""

from __future__ import annotations

import logging

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import HometouchClient
from .const import CONF_STREAM_URL, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the BTicino HOMETOUCH camera platform."""
    client: HometouchClient = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([HometouchCamera(client, entry)], True)


class HometouchCamera(Camera):
    """Camera entity for BTicino HOMETOUCH intercom video stream."""

    _attr_has_entity_name = True
    _attr_translation_key = "intercom_camera"
    _attr_name = "Videocitofono"
    _attr_icon = "mdi:cctv"

    def __init__(self, client: HometouchClient, entry: ConfigEntry) -> None:
        """Initialize the camera."""
        super().__init__()
        self._client = client
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_camera"
        self._attr_supported_features = CameraEntityFeature.STREAM

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )

    @property
    def stream_source(self) -> str | None:
        """Return the source stream URL."""
        custom_url = self._entry.options.get(
            CONF_STREAM_URL, self._entry.data.get(CONF_STREAM_URL, "")
        )
        if custom_url:
            return custom_url

        # Default fallback stream: SIP/RTSP stream from Hometouch or go2rtc
        return f"rtsp://{self._client.host}:554/live"

    async def async_create_stream(self):
        """Create stream and wake up camera via SIP session."""
        self.hass.async_create_task(self._client.async_trigger_camera())
        return await super().async_create_stream()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image from the camera."""
        # When integration is paired with go2rtc or stream component, Home Assistant handles frames
        return None

