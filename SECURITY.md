# Security Policy

## Authorized use only

Nemesis is an **offensive-capable** web-application security scanner. Use it
**only** against systems you own or are explicitly authorized to test (a written
engagement, a bug-bounty program's defined scope, or your own lab). Unauthorized
scanning may be illegal in your jurisdiction. The authors accept no liability for
misuse.

## Supported versions

Security fixes target the `main` branch. There is no long-term-support branch;
please track `main`.

## Reporting a vulnerability

If you find a vulnerability **in Nemesis itself** (not in a target you scanned):

1. **Do not** open a public issue for anything exploitable.
2. Use GitHub's **private vulnerability reporting**
   (repository → *Security* → *Report a vulnerability*), or
3. Contact the maintainers privately.

Please include: affected version/commit, reproduction steps, and impact.
We aim to acknowledge reports within a few days.

## Our own supply chain

- Every push/PR runs **CodeQL** (`security-and-quality`) and **Bandit** SAST.
- **pip-audit** checks runtime dependencies for known CVEs.
- **Dependabot** proposes weekly dependency and GitHub-Actions updates.
