# metacubex/utls with fixes

Base: github.com/metacubex/utls branch `v1.9.0-mod-meta`, commit a6a364afbd13 (2026-10-26), without tests,
test data and images. go.mod requires it as `v1.9.0-vpn4tv.1` and replaces it with this directory, so stack
traces of -trimpath builds name `utls@v1.9.0-vpn4tv.1`.

Changes on top of the base:

1. CVE-2026-32283 (golang/go#78334, Go commit 7cafb4140d56): a KeyUpdate with update_requested followed by
   another handshake message in the same record deadlocked the connection on `c.out`
   (`setReadTrafficSecret(..., locked bool)`; conn.go, handshake_client_tls13.go, handshake_server_tls13.go).
2. Certificate decompression read the message with a single `Read`, which returns at most one 32 KiB flate
   window: compressed certificate messages larger than that failed. Ported from refraction-networking/utls
   6ad535ea592a and de505bd33437 (`io.ReadFull`, excess output and trailing input are rejected;
   u_handshake_client.go).

To move to a newer base, copy the module again the same way and re-apply the changes that upstream lacks.
