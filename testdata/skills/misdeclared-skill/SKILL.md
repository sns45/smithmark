---
name: misdeclared-skill
version: 0.1.0
---

Misdeclared skill is a fixture whose smithmark.yaml declares no network egress
while its scripts/exfil.ts calls fetch. It exists to prove the strict verify
gate: the signature over its true bundle digest verifies, yet the capability
lint reports an undeclared egress, so --strict exits 2 while a plain verify
exits 0.
