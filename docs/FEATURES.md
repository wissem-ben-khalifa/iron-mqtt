# IDS features

Source of truth: `ids/features.py` (`FEATURES`). One row = one client IP talking to the
broker during one aligned 5-second window. "up" = client → broker, "down" = broker → client.
Only what is visible on the wire under TLS is used: no MQTT fields, no payload content,
no IPs or ports as features (the client IP is only the grouping key and the label join key).

## Feature provenance and robustness (core tier, part B)

Purpose: decide which features a **robust** IDS should rely on. For each feature: what
process produces its value, and whether a **compromised device that stays functional**
(adversary B: genuine device software, genuine certificate, still able to publish) could
influence it. Classes:

- **NO** — set by the protocol, the network stack or the broker; the device cannot change it.
- **PARTIAL** — mostly set by the broker or the stack, but shifted by the device's own choices
  (e.g. the QoS it requests).
- **YES** — produced directly by the device's own sending behaviour.

"Importance" is the trained model's (`m0001`, gradient boosting, train-A) feature importance,
read from `models/m0001.joblib` — a real number, not an estimate.

| Feature | Produced by | Influence | Reason | m0001 importance |
|---|---|---|---|---|
| `payload_up` | device software volume + TLS record framing | **YES** | sum of what the device chooses to send | **0.412** |
| `iat_up_min` | device send timing + TCP coalescing | **YES** | timing of the device's own writes | **0.362** |
| `payload_up_std` | device message sizes + TLS framing | **YES** | spread of the device's own message sizes | **0.086** |
| `data_pkts_up` | device writes, segmented by the TCP stack | **YES** | follows how often the device writes | **0.079** |
| `bytes_up` | device volume + TLS + TCP/IP headers + its ACKs | **YES** | dominated by device volume; headers add a fixed per-packet floor | **0.061** |
| `pkts_up` | device writes + the device's TCP ACKs | **YES** | data packets plus ACKs the device's stack emits | 0 |
| `payload_up_mean` | device message sizes + TLS framing | **YES** | device message sizes; TLS sets a 24 B minimum per record | 0 |
| `payload_up_max` | device message sizes + TCP segmentation (MSS) | **YES** | device sizes, capped by the MSS the stack negotiates | 0 |
| `iat_up_mean` | device send timing | **YES** | timing of the device's own writes | 0 |
| `iat_up_std` | device send timing | **YES** | timing of the device's own writes | 0 |
| `active_s` | device send timing within the window | **YES** | when inside the window the device sends | 0 |
| `syn_up` | device connection management | **YES** | the device decides when to (re)connect; each connect costs a full mTLS handshake | 0 |
| `fin_up` | device connection management | **YES** | the device decides when to disconnect | 0 |
| `conns` | device connection management | **YES** | number of parallel sessions the device opens | 0 |
| `pkts_down` | broker replies + broker TCP ACKs | **PARTIAL** | broker-generated, but scales with what the device sends and the QoS it requests | 0 |
| `bytes_down` | broker replies + headers | **PARTIAL** | as above | 0 |
| `payload_down` | broker MQTT replies (CONNACK, PUBACK, commands) | **PARTIAL** | broker-generated; QoS 1/2 adds one reply per message, QoS 0 none | 0 |
| `bytes_ratio_up_down` | ratio of a YES and a PARTIAL quantity | **PARTIAL** | inherits both; strongly shifted by the requested QoS | 0 |
| `rst_any` | either side's TCP stack | **PARTIAL** | the broker or the device's stack can reset; the device can provoke resets | 0 |

**Finding.** None of the 19 current features is in the NO class. The model `m0001`
places **100% of its importance on five YES features** (`payload_up`, `iat_up_min`,
`payload_up_std`, `data_pkts_up`, `bytes_up`). It works on the MVP flood because the attacker
made no attempt to look benign. It is therefore the model the robustness evaluation must
test, and the reason hardening is needed (see "Robust-feature models" in `docs/RESULTS.md`).

**What constrains a YES feature anyway.** Influence is not unlimited: a flood that is to
stay effective must keep its *aggregate* delivered volume high (the M5 impact only appeared at
≈ 20,000 msg/s). Features that measure that aggregate over a longer horizon are harder to
move without giving up the attack than per-window shape features are. That property —
"cannot be changed without abandoning the attack's goal" — is the robustness criterion used below.

### System-level and relative signals (implemented 2026-10-16, `ids/robust_features.py`)

Used by the robust-feature models m0002–m0006 (results: `docs/RESULTS.md`, "Robust-feature
models"). Rows marked *not implemented* remain candidates.

| Signal | Produced by | Influence | Reason |
|---|---|---|---|
| `fleet_latency_ms` — honest-device latency, median of per-device medians | ingest + other devices | **NO** (SYSTEM) | the effect on other devices; one device supplies one of ~10 medians |
| `ingest_rwnd_min`, `ingest_zero_win` — ingest TCP backpressure | ingest's TCP stack | **NO** (SYSTEM) | set by ingest under load; got 0 weight at the test-B rate (ingest not saturated at 2,000/s) |
| `active_sources` — sources sending in the window | other devices | **NO** (SYSTEM) | the device adds only itself |
| `fanout_payload` — broker → ingest bytes | broker | PARTIAL | broker-produced, but scales with what is published |
| `fleet_up_payload` — all sources' upstream bytes | all sources | PARTIAL | one device adds to the sum |
| `share_up` — this source's share of fleet upstream | the device / the fleet | PARTIAL | the numerator is the device's own volume |
| per-identity volume over a long horizon (e.g. 5 min) — *not implemented* | device volume, aggregated | PARTIAL | lowering it means lowering the flood itself |
| deviation from the device type's benign profile — *not implemented* | device behaviour vs fleet baseline | PARTIAL | the profile (p1) is fixed by the fleet, not by the attacker |
| TLS fingerprint (JA3/JA4) — Suricata rules, not a model feature | genuine client software | **NO** (for this adversary) | identical to the fleet by construction (Core A) — robust, but uninformative here |

## Known transfer gaps (from the feature spike)

See `docs/RESULTS.md` → "Feature spike". Summary:

| Feature group | Transfers fleet ↔ MQTTset? | Why |
|---|---|---|
| sizes (`bytes_*`, `payload_*`, `bytes_ratio_up_down`) | **No** | TLS record overhead; MQTTset flood is 32 KB loopback-style segments |
| counts (`pkts_*`, `data_pkts_up`) | Partly | MQTTset benign clients are ~5× chattier and very uniform |
| timing (`iat_*`, `active_s`) | Partly | same as counts |
| connections (`syn_up`, `fin_up`, `conns`, `rst_any`) | Yes, but uninformative | one long-lived connection per client in both |
