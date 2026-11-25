# Benchmarks & Detector Evaluation

Measured locally via `npm run benchmark` (`backend/src/demo/benchmark.ts`, 1,000 iterations in-process).

## In-Process Gateway Pipeline Overhead
*(Excludes upstream MCP stdio/HTTP round-trip and external DB I/O)*

| Path | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | --- | --- | --- |
| Allow path (RBAC + Rate Limit + Request Inspector) | 0.002 | 0.005 | 0.019 |
| With response filters (Secrets + PII + Injection) | 0.005 | 0.011 | 0.042 |

## Detector Evaluation (10 Labelled Fixtures)
- **True Positives (TP)**: 5
- **False Positives (FP)**: 0
- **True Negatives (TN)**: 5
- **False Negatives (FN)**: 0
- **Precision**: 1.000
- **Recall**: 1.000

> **Note**: This evaluation uses a small synthetic fixture set (5 benign, 5 malicious). Pattern-based detectors are risk-reduction controls and can be bypassed by obfuscation.
