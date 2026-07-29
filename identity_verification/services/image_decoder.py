from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

import cv2
import numpy as np

from .exceptions import IdentityVerificationError

MAX_IMAGE_BYTES = 6 * 1024 * 1024


class ImageDecodingError(IdentityVerificationError):
    """Raised when a submitted image cannot be decoded into a usable frame."""


@dataclass
class DecodedImage:
    frame: np.ndarray  # BGR, as returned by OpenCV
    width: int
    height: int
    byte_size: int


class ImageDecoder:

    @classmethod
    def decode(cls, base64_image: str) -> DecodedImage:
        if not base64_image or not isinstance(base64_image, str):
            raise ImageDecodingError("No image data was provided.")

        payload = base64_image
        if payload.startswith("data:"):
            # Strip a data URL prefix such as "data:image/jpeg;base64,"
            _, _, payload = payload.partition(",")

        try:
            raw_bytes = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ImageDecodingError("Image is not valid base64.") from exc

        if not raw_bytes:
            raise ImageDecodingError("Decoded image is empty.")

        if len(raw_bytes) > MAX_IMAGE_BYTES:
            raise ImageDecodingError("Image exceeds the maximum allowed size.")

        buffer = np.frombuffer(raw_bytes, dtype=np.uint8)
        frame = cv2.imdecode(buffer, cv2.IMREAD_COLOR)

        if frame is None:
            raise ImageDecodingError("Image could not be decoded as JPEG/PNG.")

        height, width = frame.shape[:2]

        return DecodedImage(
            frame=frame,
            width=width,
            height=height,
            byte_size=len(raw_bytes),
        )