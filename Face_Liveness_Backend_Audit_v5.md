# Face Liveness — Backend Audit and Green Light (v5)

For: Gaurav
From: Vikram
Repo: OneSmarterInc/face-liveness-backend-gaurav-dhale
Reviewed at: 3d0e917 ("face-liveness backend implementation")

---

## Green light — proceed to face recognition

This is the audit you asked to gate the next step on, and it passes. The backend does the thing that actually matters: the server recomputes the liveness verdict from the evidence and never trusts a client result. You can move on to face recognition. Read the hardening list below first, because two items should be folded in along the way, but nothing here blocks you.

## What you got right, specifically

The client sends no verdict anymore, and the LivenessEngine recomputes pass/fail from the telemetry itself. It slices the telemetry to each challenge's own time window and actually checks the motion: for a turn it runs a state machine over the yaw series that requires the face to start centered, cross the threshold, and hold there for a minimum number of stable frames, and it only passes the whole session if every challenge passes and the mean score clears the minimum. That's real evaluation, not a presence check.

The challenge order is server-owned. It's shuffled per session at creation and stored on the session, and the validator rejects the attempt if the submitted sequence or the executed event order doesn't match the issued order exactly. That's what makes a pre-recorded or replayed clip fail.

The serializer refuses to let the client smuggle in a decision. Embedding, biometric_template, face, landmarks, and raw frame fields are banned outright, unexpected keys are rejected, and the pass/fail comes only from server-computed stages. This is the discipline the last three notes were about, and it's enforced at the door.

And the proof you return is real. ML-DSA-44 (the FIPS 204 post-quantum signature) over a canonical serialization that binds the record hash, an append-only SHA3-256 hash-chain head, the challenge, a freshness timestamp, and a signing epoch. A tamper-evident, post-quantum-signed receipt is ahead of where it needed to be, and it points straight at where the vault is going. Nicely done.

## Fix this one before it's leaned on

Single-use is not atomic. The nonce check, the status check, and the consumed_at check are all read-only reads, with no row lock and no atomic consume. Two completes for the same session racing each other can both pass those checks before either one writes consumed_at. The unique payload hash and the one-to-one session on the result will stop a byte-identical resubmit, but not a concurrent race or a re-serialized duplicate. Wrap the complete flow in a select_for_update on the session and set consumed_at inside the same transaction, or put a DB unique constraint on the session result and handle the integrity error. Single-use is the backbone of your replay defense, so it needs to be race-proof.

## Guardrails for the face-recognition phase you're about to build

You already have the right instinct wired in — keep it. When you build the embedding stage, the embedding is generated server-side from the uploaded frame, never accepted from the client, and the banned-fields rule that already blocks a client embedding stays exactly as it is. Two more that matter once real images flow: recompute image quality on the server rather than trusting the client's quality_score, sharpness, and brightness (they're client-asserted today, and face_confidence even defaults to 1 when omitted, which should be 0 or required), and validate the decoded frame strictly — size caps and safe decoding — before it touches the model.

Store the embedding encrypted at rest. You already have a working AES-GCM module sitting dormant; the embedding stage is where it gets wired in. The full vault design — the key handling and how an aging template gets updated under encryption — is a decision Vikram and I will hand you separately, so build the seam to encrypt-on-write and we'll slot the specifics in. Don't design the key management yourself yet.

## Small cleanups

Remove the stray print statements in the view and the engine. Switch the challenge shuffle from the default random module to a cryptographically secure one (secrets or SystemRandom). And as defense-in-depth on replay, consider hashing the decoded image on its own and adding a freshness bound, so a re-encoded frame with jittered telemetry doesn't slide through the byte-exact fingerprint.

## The line

The server reproduces the result from the evidence now, which is the whole point, and the proof it signs makes that result something we can stand behind later. Keep that same posture into recognition: the trusted side computes the biometric, the client only ever hands up raw material. Good work — this was the hard part, and you got it right.
