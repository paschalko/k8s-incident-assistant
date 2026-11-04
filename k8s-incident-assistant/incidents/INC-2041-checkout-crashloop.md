# INC-2041 – checkout-api pods restarting, checkout errors spiking

- **Severity:** SEV-2
- **Reported:** 2026-10-30 14:22 UTC by on-call (PagerDuty alert `CheckoutErrorRate>5%`)
- **Cluster / namespace:** `staging-eu-1` / `shop` *(fixture data – no live cluster)*
- **Service:** `checkout-api` (Deployment, 3 replicas)
- **Customer impact:** ~18% of checkout requests returning 502/503 from the ingress.

## Symptoms
- `checkout-api` pods show `CrashLoopBackOff`; restart counts climbing (7–9 per pod in 20 min).
- Grafana: pod memory climbs steadily for ~3–4 minutes after start, then the pod disappears.
- Some logs mention timeouts to `payment-gateway`.

## Recent changes
- 2026-10-30 13:58 UTC – Argo CD synced `checkout-api` **v2.14.0** (was v2.13.2).
  Release notes: "Add in-memory product catalogue cache for faster price lookups (`CACHE_MAX_ITEMS`)."
- 2026-10-29 – `payment-gateway` certificate rotated (no alerts since).

## Actions taken so far
- None. On-call requested an AI-assisted analysis before acting.

## Attachments
- `logs/INC-2041/checkout-api-7d9f8b6c5-x2k4p.previous.log` (`kubectl logs --previous`)
- `logs/INC-2041/describe-pod-checkout-api-7d9f8b6c5-x2k4p.txt`
- `logs/INC-2041/events-shop.txt`
- `logs/INC-2041/deployment-checkout-api.yaml`
