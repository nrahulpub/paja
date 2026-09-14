---
"@kehto/services": minor
---

Add ContextVM CEP-22 oversized-transfer and CEP-41 open-stream framing to
the Nostr CVM transport with strict admission and bounded reassembly:
progress frames are only admitted for tokens this client issued to the
signing server, reassembly buffers live on their originating request, the
complete CEP-22 start metadata (render completion mode, sha256 digest,
totals) is required before buffering, actual chunk/byte and active-transfer
limits are enforced with hard expiry, and frame state is released on
completion, timeout, terminal stream frames, and dispose.
