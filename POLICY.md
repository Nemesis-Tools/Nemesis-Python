# Rules of Engagement (테스트 정책)

Nemesis scans real systems. All testing must **prove that a vulnerability is
possible and then stop** — never cause real-world impact. These rules are
encoded in [`core/roe.py`](core/roe.py) so modules and reports reference them
consistently.

## 1. SSRF — 검증용 도메인으로 가능성만 증명

- SSRF 취약점 테스트 시 **검증용 도메인**
  `http://bugbounty.toss.sb/bugbounty-{credential}` 을 사용하여
  **취약점에 대한 가능성만** 증명합니다.
- Confirm the out-of-band callback to the verification domain only. Do **not**
  pivot to internal services, cloud metadata, or third-party hosts, and do
  **not** exfiltrate data.
- If no verification/canary domain is configured, the SSRF module skips itself
  (see [`core/oob.py`](core/oob.py)).

## 2. 금액 변조 — 최소 금액으로 가능성만 증명

- 금액변조(price/amount tampering) 취약점 테스트 시 **최소 금액(100원)** 으로
  **가능성만** 증명합니다.
- Never transact larger sums to "demonstrate" impact — the minimum amount is
  sufficient proof.

## Authorized use only

Only test targets you own or are explicitly authorized to test (a written
engagement or a bug-bounty program's defined scope). See [SECURITY.md](SECURITY.md).
