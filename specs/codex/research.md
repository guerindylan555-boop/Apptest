# Research Log — Web UI Stream Fix

## Media Source handling of scrcpy raw H.264

Decision: Convert the scrcpy output to fragmented MP4/WebCodecs-friendly frames before handing data to the browser (no direct raw Annex B appends).
Rationale: Media Source Extensions require ISO BMFF fragments whose metadata describes frame boundaries; feeding Annex B NAL units under a `video/mp4` SourceBuffer triggers decode errors and results in a black screen. Scrcpy’s raw socket stream exposes Annex B H.264 without containerisation, so an intermediary needs to package frames or expose a higher-level protocol.
Alternatives considered: Keep raw HTTP stream and hope browsers decode (fails in Chromium); switch to WebRTC (heavy setup for localhost and unnecessary for single client); use WebCodecs with manual demux (possible but significantly more work than leveraging existing ws-scrcpy tooling).

## Streaming transport selection

Decision: Re-use the `ws-scrcpy` server + `scrcpyws-client` stack to expose a WebSocket pipeline that delivers browser-ready frames and control metadata.
Rationale: The project already depends on ws-scrcpy pieces, which provide a turnkey bridge between scrcpy and the browser. Using its server avoids maintaining a custom wrapper that fails to package frames correctly and includes token validation features we need. Client libraries render to `<canvas>` and handle codec negotiation.
Alternatives considered: Maintain the bespoke HTTP wrapper and build our own muxer (high complexity, poor reliability); shell out to ffmpeg to transmux to fMP4 (adds heavy binary dependency and latency); adopt WebRTC (overkill for localhost-only, adds signalling flow).

## Test strategy coverage gap

Decision: Add backend unit coverage for stream ticket issuance and lifecycle transitions plus manual checklist for stream rendering until headless stream assertions are feasible.
Rationale: No automated coverage exists today. Verifying ticket issuance and state transitions is feasible with Jest or Vitest by mocking the session store, providing regression safety around the fix. Visual confirmation of the stream remains manual but should be documented via quickstart steps.
Alternatives considered: Skip tests (risk regression of ticket and lifecycle logic); invest in end-to-end browser automation (complex due to emulator dependency and real video frames).
