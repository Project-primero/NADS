# Understanding Aegis — what it is, how to think about it, why it matters

> Technical companions: [HOW_IT_WORKS](HOW_IT_WORKS.md) (pipeline + tests) ·
> [ARCHITECTURE](ARCHITECTURE.md) · [DETECTION_CATALOG](DETECTION_CATALOG.md)

## 1. The one-sentence mental model

**Aegis watches network traffic the way a bank security guard watches cameras:
it learns what "normal" looks like, recognizes known criminal faces
(signatures), notices strange behavior (anomaly ML), and radios the control
room (dashboard) with a severity rating.**

Everything in the repo is one of three things: **eyes** (capture), **brain**
(detection), or **voice** (alerts + dashboard).

## 2. How to understand each part (read in this order)

| # | Question | Answer | File to open |
|---|---|---|---|
| 1 | Where does data enter? | `PacketCapture` — live NIC sniffing or a simulator that replays 14 attack types + benign traffic | `backend/capture/packet_capture.py` |
| 2 | How is chaos organized? | `FlowManager` groups packets into 5-tuple conversations (who→whom, which service) | `backend/flow/flow_manager.py` |
| 3 | What is measured? | 41 numbers per conversation: speed, sizes, flag ratios, port variety, payload clues | `backend/flow/feature_extractor.py` |
| 4 | How are *known* attacks caught? | 30 sliding-window rules — e.g. "15 ports in 60s = scan" | `backend/detection/signature_engine.py` |
| 5 | How are *unknown* attacks caught? | ML model scores how far a conversation deviates from normal baseline | `backend/detection/models/hybrid_model.py` |
| 6 | Who decides the final verdict? | `correlate()` fuses both: signature wins, ML confirmation adds +10 → 0–100 threat score | `backend/detection/correlation.py` |
| 7 | How do analysts see it? | WebSocket pushes every alert in ~1s to the React SOC dashboard | `frontend/src/components/Dashboard.tsx` |

**Suggested exercise:** open the dashboard, pick one alert (say Log4Shell),
and trace it backwards — dashboard → `/api/alerts` → `AlertManager` →
`correlate()` → the rule in `signature_engine.py` that fired. Ten minutes of
this teaches more than reading every file.

## 3. Why each layer matters (importance)

- **Signatures (fast, precise).** Known attacks — port scans, floods, brute
  force, Log4Shell — must be caught in under a second with near-zero false
  positives. This is what stops the attacks happening *right now*.
- **ML anomaly (broad, adaptive).** Signatures can't catch zero-days. The
  Isolation Forest flags "weird for this network" even with no matching rule —
  the only defense against novel exfiltration or custom malware.
- **Correlation (anti-fatigue).** A SOC that cries wolf gets ignored. Fusing
  two independent engines into one scored verdict is what makes alerts
  *actionable* instead of noise.
- **MITRE + remediation on every alert.** A junior analyst seeing
  `T1190 — Block src IP at WAF, patch input handling` can respond correctly
  without senior help. That mapping is the difference between a demo and a tool.
- **Live dashboard.** Detection nobody looks at is worthless. Sub-second
  WebSocket delivery plus search/filter/offender views turns raw alerts into
  decisions: *who do I block first?*

## 4. Why this project matters (bigger picture)

1. **Real threat landscape.** Ransomware crews, botnets (Mirai-style Telnet
   scans), and mass exploits (Log4Shell) all begin with exactly the patterns in
   the catalog — scanning, brute force, C2 beaconing, exfiltration. Detecting
   these early is how breaches get stopped at reconnaissance instead of ransom.
2. **Defense in depth, demonstrated.** The system embodies the core security
   principle of layered defense (rules + statistics + ML + human UI) in one
   runnable codebase.
3. **Portfolio / academic value.** It touches networking (packets/flows),
   backend engineering (FastAPI/WS/SQLite), machine learning (unsupervised
   anomaly detection + sequence models), and frontend (real-time React) —
   a complete vertical slice employers and examiners can actually run.
4. **Operational honesty.** Documented limits (TLS blindness, single-node
   throughput, tuning trade-offs in [DEPLOYMENT](DEPLOYMENT.md)) show security
   maturity: knowing what your detector *can't* see is as important as what it can.

## 5. Explain it to someone else (30-second version)

> "It's a security camera system for computer networks. It watches all traffic,
> recognizes 30 known attack patterns instantly, uses AI to spot suspicious
> behavior it has never seen before, scores each threat 0–100 with a fix-it
> instruction, and shows everything live on a dashboard — so analysts can block
> attackers in seconds instead of discovering the breach months later."
