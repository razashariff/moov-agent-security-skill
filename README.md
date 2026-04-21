# Moov Agent Security Skill

AI skill for securing agent-initiated payment operations on the Moov platform. Gives your AI coding assistant knowledge of cryptographic agent identity, message signing, and sanctions screening patterns.

## What it covers

- **Agent identity verification** -- X.509 certificates with trust levels (L0-L4)
- **MCPS message signing** -- tamper-evident ECDSA signatures on all payment responses
- **Sanctions screening** -- pre-transfer screening via moov-io/watchman
- **Audit trail** -- hash-chained compliance logs (JSON, syslog, SIEM export)
- **Moov Issuing security** -- trust-based spend controls on agent cards

## Quick install

### Any AI coding assistant

Download the skill file and place it where your AI assistant reads context files:

```bash
curl -sL https://raw.githubusercontent.com/razashariff/moov-agent-security-skill/main/SKILL.md \
  -o moov-agent-security-SKILL.md
```

Place in your project's AI context directory as appropriate for your tooling.

## Already integrated

MCPS signing and AgentPass identity verification are already merged into moov-io/watchman:

- [PR #730 -- MCPS message signing](https://github.com/moov-io/watchman/pull/730)
- [PR #733 -- AgentPass agent identity](https://github.com/moov-io/watchman/pull/733)

## Author

Raza Sharif, CyberSecAI Ltd
raza.sharif@outlook.com
