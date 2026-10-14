"""Camera platform for BTicino HOMETOUCH integration."""

from __future__ import annotations

import asyncio
import logging
import os

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

    entities = [
        HometouchCamera(
            client=client,
            entry=entry,
            devaddr="20",
            name="Telecamera Cancello",
            unique_id_suffix="camera",
            icon="mdi:cctv",
        ),
        HometouchCamera(
            client=client,
            entry=entry,
            devaddr="21",
            name="Telecamera Portoncino",
            unique_id_suffix="camera_secondary",
            icon="mdi:camera-wireless",
        ),
    ]

    async_add_entities(entities)


class HometouchCamera(Camera):
    """Camera entity for BTicino HOMETOUCH intercom video stream."""

    _attr_has_entity_name = True

    def __init__(
        self,
        client: HometouchClient,
        entry: ConfigEntry,
        devaddr: str,
        name: str,
        unique_id_suffix: str,
        icon: str,
    ) -> None:
        """Initialize the camera."""
        super().__init__()
        self._client = client
        self._entry = entry
        self._devaddr = devaddr
        self._attr_name = name
        self._attr_icon = icon
        self._attr_unique_id = f"{entry.entry_id}_{unique_id_suffix}"
        self._attr_supported_features = CameraEntityFeature.STREAM
        self._last_image: bytes | None = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"BTicino HOMETOUCH ({client.host})",
            manufacturer="BTicino / Legrand",
            model="HOMETOUCH (3488)",
            configuration_url=f"http://{client.host}",
        )

    async def stream_source(self) -> str | None:
        """Return the source stream URL."""
        custom_url = self._entry.options.get(
            CONF_STREAM_URL, self._entry.data.get(CONF_STREAM_URL, "")
        )
        if custom_url:
            return custom_url

        sdp_path = f"/tmp/bticino_camera_{self._devaddr}.sdp"
        if os.path.exists(sdp_path):
            return sdp_path
        if os.path.exists("/tmp/bticino_camera.sdp"):
            return "/tmp/bticino_camera.sdp"
        return f"rtsp://{self._client.host}:554/live"

    async def async_create_stream(self):
        """Create stream and wake up camera via SIP session."""
        if not self._client.is_video_active or self._client.active_devaddr != self._devaddr:
            self._client.video_ready_event.clear()
            self.hass.async_create_task(
                self._client.async_trigger_camera(duration=10, devaddr=self._devaddr)
            )
            try:
                await asyncio.wait_for(self._client.video_ready_event.wait(), timeout=6.0)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout attesa attivazione video SIP per stream %s", self.name)
        return await super().async_create_stream()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image from the camera."""
        if not self._client.is_video_active or self._client.active_devaddr != self._devaddr:
            if self._last_image is not None:
                return self._last_image

            self._client.video_ready_event.clear()
            self.hass.async_create_task(
                self._client.async_trigger_camera(duration=10, devaddr=self._devaddr)
            )
            try:
                await asyncio.wait_for(self._client.video_ready_event.wait(), timeout=6.0)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout attesa attivazione video SIP per snapshot %s", self.name)
                return self._last_image

        sdp_path = f"/tmp/bticino_camera_{self._devaddr}.sdp"
        if not os.path.exists(sdp_path):
            sdp_path = "/tmp/bticino_camera.sdp"

        if not os.path.exists(sdp_path):
            return self._last_image

        try:
            from homeassistant.components.ffmpeg import async_get_image
            img = await async_get_image(
                self.hass,
                sdp_path,
                extra_cmd="-protocol_whitelist file,udp,rtp,crypto",
            )
            if img:
                self._last_image = img
            return img or self._last_image
        except Exception as exc:
            _LOGGER.debug("Errore acquisizione frame FFmpeg per %s: %s", self.name, exc)
            return self._last_image

