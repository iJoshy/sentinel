"""Send a sample completed analysis to a real URL (webhook.site, httpbin, etc.).

Run from ``backend/``::

    WEBHOOK_URL=https://webhook.site/<your-uuid> uv run python -m integrations.manual_dispatch

Optional::

    INTEGRATION_TYPE=slack          # default: generic_webhook
    SENTINEL_PUBLIC_URL=http://localhost:3000   # adds dashboard_url in generic payload
    INCIDENT_TITLE=edge-gateway.txt             # appears as incident_title in JSON / Slack
    INCIDENT_SOURCE=upload
"""

from __future__ import annotations

import os
import sys

from integrations.dispatcher import dispatch_all, synthetic_test_analysis


def main() -> int:
    url = (os.getenv("WEBHOOK_URL") or "").strip()
    if not url:
        print("Set WEBHOOK_URL to your webhook.site URL (or https://httpbin.org/post).", file=sys.stderr)
        return 1
    itype = (os.getenv("INTEGRATION_TYPE") or "generic_webhook").strip().lower()
    if itype not in ("slack", "generic_webhook"):
        print("INTEGRATION_TYPE must be slack or generic_webhook", file=sys.stderr)
        return 1

    row = {
        "type": itype,
        "enabled": True,
        "config": {"webhook_url": url},
    }
    analysis = synthetic_test_analysis()
    title = (os.getenv("INCIDENT_TITLE") or "").strip()
    source = (os.getenv("INCIDENT_SOURCE") or "").strip()
    print(f"Dispatching {itype} → {url[:60]}…")
    dispatch_all(
        [row],
        analysis,
        incident_title=title,
        incident_source=source,
    )
    print("Done — check your receiver for a new request.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
