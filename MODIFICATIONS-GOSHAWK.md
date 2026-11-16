# Goshawk modifications — 2026-11-16

This maintained Apache-2.0 fork adds BitcoinSV transaction policy and ForkID-zero
signing/verification, P2PKH-only address-wallet selection, bare-multisig/data-output
validation, and rejection of P2SH/witness templates and Bitcoin sighashes. BIP125
replacement is disabled. The editor's internal PSBT container is retained with BSV
checks. Currency unit is BSV. ElectrumSVP-compatible payment URIs require `?sv`.
BIP32 and signed-message protocol constants and the original LICENSE are unchanged.
See the parent Goshawk repository's validation and payment-compatibility records.
