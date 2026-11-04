# Runbook: ImagePullBackOff / ErrImagePull

## Symptoms
- Pod status `ImagePullBackOff` or `ErrImagePull`; events `Failed to pull image`.

## Diagnose (read-only)
1. `kubectl describe pod <pod> -n <ns>` – read the pull error (not found / unauthorized / timeout).
2. Check the image tag exists in the registry and the `imagePullSecrets` on the ServiceAccount.

## Remediate
- Wrong tag → fix the tag in Git. Auth error → platform team rotates the pull secret.
