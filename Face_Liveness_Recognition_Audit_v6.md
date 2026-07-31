# Face Recognition — Backend Audit (v6)

For: Gaurav
From: Vikram
Repo: OneSmarterInc/face-liveness-backend-gaurav-dhale
Reviewed at: 011dffa ("face registration backend module configured")

---

## First — the architecture is right, and part of it is ahead of schedule

The recognition module is built the way it should be, and I want to be specific about what you got right before the two things that have to change.

The embedding is generated entirely on the server from the uploaded frame. Decode, InsightFace alignment to 112x112 with a single-face check, a real quality gate that recomputes blur, brightness, contrast and pose from the pixels rather than trusting any client number, and then real ArcFace w600k_r50 inference producing a 512-dimension L2-normalized vector. Nothing accepts a client-supplied embedding. That's the whole point of moving recognition server-side, and you did it cleanly.

And you encrypted the template at rest with AES-GCM, with the associated data bound to the account and the model name and version. That means a stored template is authenticated and can't be lifted and replayed against a different account. That is exactly the vault posture we're heading toward, and you built it earlier than the plan asked for. Good.

So this note isn't "start over." It's two defects on top of a correct foundation.

## The one that has to move: enrollment isn't bound to a live human

This is the important one, because it's the one thing the whole system exists to guarantee. RecognitionService only checks that the caller owns the session. It does not check that the session actually passed liveness — and you know this, because you left the comment marking the exact spot where the check belongs.

Here is what that opens. An authenticated student creates a session, skips the liveness challenges entirely, and posts a plain photograph to /identity/register/. The server aligns it, embeds it, encrypts it, and stores it as their enrolled face. A biometric gets enrolled with no proof that a live person was ever in front of the camera. That is precisely the attack liveness is supposed to make impossible, and right now registration doesn't require liveness at all. Verify has the same hole — it records whether the session passed liveness but doesn't refuse when it didn't.

The fix is in the place you already flagged. Before register or verify does any work, require the session to be owned by the account, to have status COMPLETED (liveness passed), to not be expired, and to be single-use for this step — consume it so one liveness pass can't be replayed to enroll or verify repeatedly. Enrollment and verification should both refuse to run on a session that didn't just prove a live human. That single gate is what turns all the good recognition code into a real identity guarantee.

## The functional bug: verification can never pass

The similarity threshold is set to 5.0, but cosine similarity only ranges from minus one to one. So the check score greater-than-or-equal-to 5.0 is never true, and every verification fails. It's fail-closed, so it's safe rather than dangerous, but recognition simply doesn't work as written. Set a real ArcFace cosine threshold — somewhere around 0.3 to 0.4 to start — read it from settings the way the model path is, and then calibrate it against real same-person and different-person pairs using the APCER and BPCER discipline from the internal standard. Don't leave the number hardcoded; it's the single most important tuning knob in the whole matcher.

## Hardening — not blockers, but do them here

The image decoder caps input at 6 MB of bytes but not pixels, so a small file can still decode to a huge image and blow up memory. Add a megapixel cap and a JPEG/PNG format allowlist before decoding. Assert that the embedding really is 512-dimensional so a wrong or swapped model can't silently pass a different-length vector into the store. Carry through the single-use atomicity fix from the last note — a row lock on the session and an atomic consume — which now also covers consuming the session at registration. And the build artifacts are back: there's a 162 KB identity_verification.zip and a large payload.txt committed on the backend, plus src.zip has returned on the frontend. Gitignore all three and remove them so they stop coming back.

## The line

The crown jewel is that a biometric can only be enrolled, and only be matched, by a live human who was actually present. Everything you built — the server-side embedding, the encrypted template, the quality gate — is the machinery for that guarantee. The one gate that makes it true, the liveness-passed session check, is the piece that's missing. Add it, fix the threshold so matching works, and this is real.
