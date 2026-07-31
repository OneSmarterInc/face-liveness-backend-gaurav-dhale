from __future__ import annotations

import base64
import binascii
import io
from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image

from .exceptions import IdentityVerificationError

MAX_IMAGE_BYTES = 6 * 1024 * 1024
MAX_MEGAPIXELS = 25

_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class ImageDecodingError(IdentityVerificationError):
    """Raised when a submitted image cannot be decoded into a usable frame."""


@dataclass
class DecodedImage:
    frame: np.ndarray 
    width: int
    height: int
    byte_size: int


class ImageDecoder:

    @classmethod
    def _check_megapixels(cls, raw_bytes: bytes) -> None:
        try:
            with Image.open(io.BytesIO(raw_bytes)) as header:
                width, height = header.size
        except Exception as exc:
            raise ImageDecodingError("Image header could not be read.") from exc

        megapixels = (width * height) / 1_000_000
        if megapixels > MAX_MEGAPIXELS:
            raise ImageDecodingError(
                f"Image resolution ({width}x{height}) exceeds the "
                f"{MAX_MEGAPIXELS}MP limit."
            )

    @classmethod
    def decode(cls, base64_image: str) -> DecodedImage:
        if not base64_image or not isinstance(base64_image, str):
            raise ImageDecodingError("No image data was provided.")

        payload = base64_image
        if payload.startswith("data:"):
            _, _, payload = payload.partition(",")

        try:
            raw_bytes = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ImageDecodingError("Image is not valid base64.") from exc

        if not raw_bytes:
            raise ImageDecodingError("Decoded image is empty.")

        if len(raw_bytes) > MAX_IMAGE_BYTES:
            raise ImageDecodingError("Image exceeds the maximum allowed size.")

        if not (raw_bytes.startswith(_JPEG_MAGIC) or raw_bytes.startswith(_PNG_MAGIC)):
            raise ImageDecodingError(
                "Unsupported image format; only JPEG and PNG are accepted."
            )

        cls._check_megapixels(raw_bytes)

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