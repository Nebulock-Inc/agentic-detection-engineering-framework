---
name: Detection Contribution
about: Share a detection journal / FORGE example with the community (optional)
title: '[DETECTION] '
labels: detection-example
assignees: ''

---

## Detection Overview

**Detection ID:** (e.g., D-0025)
**Title:** (e.g., "Suspicious mshta.exe child process")
**MITRE ATT&CK Technique:** (e.g., T1218.005)
**Platform:** (e.g., windows, linux, macos, cloud)
**Engine:** (sigma / sql / sch_sql / composite)

## Why Share This Detection?

Explain what makes this detection valuable to share:
- Unique detection logic
- Addresses a common blind spot
- Instructive FORGE journal (good tuning / deprecation reasoning)

## Summary

Brief summary (3-5 sentences) of what it detects, the telemetry it rides on,
and any notable tuning history.

## Redaction Notice

**Important:** Please ensure all sensitive information is removed:
- [ ] No real IP addresses, hostnames, or domains
- [ ] No usernames or email addresses
- [ ] No organization IDs, customer names, or internal system names
- [ ] No credentials, API keys, access tokens, cookies, or private keys
- [ ] Queries use example/placeholder indexes and sourcetypes

## Contents

Attach or paste (sanitized):
- The catalog record (`catalog/<platform>/D-XXXX-*.yml`)
- The paired journal (`journals/D-XXXX.md`) with its FORGE stage blocks

```markdown
(Paste sanitized journal / record here)
```

## License Acknowledgment

By submitting this, you acknowledge:
- [ ] I own this content or have permission to share it
- [ ] I agree to share it under the repository's MIT LICENSE
- [ ] I understand this becomes part of the public ADEF repository
- [ ] I have removed all sensitive/proprietary information

## Note on Contribution Philosophy

ADEF is a framework to internalize, not a platform requiring contributions.
Sharing examples is **optional** and appreciated, but never expected. If you
prefer to keep your detections private, that's completely fine.
