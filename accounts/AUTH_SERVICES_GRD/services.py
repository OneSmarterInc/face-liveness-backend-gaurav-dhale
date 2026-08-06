import logging

import cv2
import numpy as np
from insightface.app import FaceAnalysis
from sklearn.metrics.pairwise import cosine_similarity

# Model loading is a server resource-lifecycle event, not a security event.
server_logger = logging.getLogger("server")

# No HTTP request is available this deep in the face-matching layer, so the
# request-scoped fields the "verbose" formatter expects are filled with
# placeholders rather than threaded down from the view.
security_logger = logging.getLogger("security")
_NO_REQUEST_CONTEXT = {"path": "AUTH_SERVICES_GRD.services.verify_face", "method": "INTERNAL", "duration": 0.0, "ip": "-"}

MODEL_NAME = "buffalo_l"  # default insightface model pack used by FaceAnalysis()
EMBEDDING_DIM = 512
FACE_VERIFICATION_THRESHOLD = 0.5  # tune against real FAR/FRR data before going live

_face_app = None  # lazy singleton, loaded once per process


class FaceDetectionError(Exception):
    pass


class NoRegisteredFaceError(Exception):
    """Raised when a user has no active enrolled face embedding to compare against."""
    pass


def get_face_app():

    global _face_app
    if _face_app is None:
        server_logger.info("Loading FaceAnalysis (%s) - first request in this process", MODEL_NAME)
        # Only detection and recognition are used here (bbox + embedding).
        # Loading the full pack would also pull in the 3d landmark and genderage
        # models, ~140MB of weights this path never touches.
        _face_app = FaceAnalysis(
            name=MODEL_NAME,
            allowed_modules=["detection", "recognition"],
        )
        _face_app.prepare(ctx_id=-1, det_size=(640, 640))
    return _face_app


def decode_image(image_file):
    image_file.seek(0)
    buffer = np.frombuffer(image_file.read(), dtype=np.uint8)
    img = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
    if img is None:
        raise FaceDetectionError("Could not decode image file")
    return img


def get_single_face_embedding(image_file):

    img = decode_image(image_file)
    app = get_face_app()
    faces = app.get(img)

    if len(faces) == 0:
        raise FaceDetectionError("No face detected in image")
    if len(faces) > 1:
        raise FaceDetectionError("Multiple faces detected; please provide a single-face image")

    face = faces[0]
    return face.embedding, face.bbox.tolist()


def verify_face(user, image_file):

    from .crypto import decrypt_embedding  # local import avoids app-load-order issues
    from ..models import FaceEmbedding

    stored_embedding = (
        FaceEmbedding.objects.filter(user=user)
        .order_by("-created_at")
        .first()
    )
    if not stored_embedding:
        security_logger.warning(
            "Face verification attempted with no registered face",
            extra={**_NO_REQUEST_CONTEXT, "status": "no_registered_face", "user": user.id},
        )
        raise NoRegisteredFaceError("No registered face found for this user")

    probe_embedding, bbox = get_single_face_embedding(image_file)

    stored_vector = decrypt_embedding(
        bytes(stored_embedding.embedding), str(user.id)
    ).reshape(1, -1)

    probe_vector = probe_embedding.reshape(1, -1).astype(np.float32)
    score = float(cosine_similarity(stored_vector, probe_vector)[0][0])

    if score < FACE_VERIFICATION_THRESHOLD:
        security_logger.warning(
            "Face verification failed (score below threshold)",
            extra={**_NO_REQUEST_CONTEXT, "status": "verification_failed", "user": user.id},
        )

    return {"score": score, "bbox": bbox}