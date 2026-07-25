# Identity Verification Payload Contract

Schema Version: 1

---

## Root

| Field              | Type   | Required | Validation         |
| ------------------ | ------ | -------- | ------------------ |
| schema_version     | int    | Yes      | Must equal 2       |
| session            | object | Yes      | Required           |
| client             | object | Yes      | Required           |
| camera             | object | Yes      | Required           |
| detector           | object | Yes      | Required           |
| challenge_sequence | array  | Yes      | Non-empty          |
| challenge_events   | array  | Yes      | Non-empty          |
| telemetry          | array  | Yes      | Minimum 20 samples |
| capture            | object | Yes      | Required           |

---

## session

| Field           | Validation                |
| --------------- | ------------------------- |
| session_nonce   | Must match issued session |
| verification_id | UUID or null              |
| started_at      | <= completed_at           |
| completed_at    | <= session expiry         |

---

## client

| Field       | Validation          |
| ----------- | ------------------- |
| platform    | android / ios / web |
| app_version | Non-empty           |
| browser     | Non-empty           |
| os          | Non-empty           |

---

## camera

| Field             | Validation |
| ----------------- | ---------- |
| resolution.width  | >0         |
| resolution.height | >0         |
| fps               | >0         |

---

## detector

| Field    | Validation |
| -------- | ---------- |
| provider | MediaPipe  |
| version  | Non-empty  |

---

## challenge_sequence

- Must exactly equal issued sequence.
- Order cannot change.
- No duplicates.

---

## challenge_events

Each object contains

- challenge
- started_at
- completed_at

Rules

- Must appear in issued order.
- No duplicates.
- completed_at >= started_at.

---

## telemetry

Each sample

| Field           | Validation |
| --------------- | ---------- |
| t               | >=0        |
| yaw             | -90..90    |
| pitch           | -90..90    |
| roll            | -180..180  |
| ear_left        | 0..1       |
| ear_right       | 0..1       |
| face_detected   | boolean    |
| face_confidence | 0..1       |

Rules

- Minimum 20 samples.
- Time ordered.
- No future timestamps.
- Continuous sampling.

---

## capture

| Field           | Validation  |
| --------------- | ----------- |
| frame_timestamp | Required    |
| quality_score   | 0-100       |
| sharpness       | >=0         |
| brightness      | 0-255       |
| image           | Base64 JPEG |

---

## Rejected Payload Fields

The API immediately rejects payloads containing

- file
- files
- frame
- frames
- photo
- photos
- video
- videos
- face
- faces
- embedding
- biometric_template
- face_template
- raw_detection
- landmarks
- face_geometry

---

## Server Guarantees

The server never trusts

- quality_score
- sharpness
- brightness

These are recomputed server-side before recognition.
