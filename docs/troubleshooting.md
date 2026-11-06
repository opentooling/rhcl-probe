# Troubleshooting

The console runs with an Istio sidecar, and with `mesh.egress.registryOnly: true` (the default)
that sidecar only lets it reach hosts in the mesh's registry. Both shape what the checks see,
so a check can fail even though the same request works with curl from your laptop or a node.
The cases below are the ones seen so far.

Commands use `<ns>` for the release namespace, `<release>` for the Helm release name and
`<console-pod>` for the console's pod. The `istio-proxy` image has no shell tools beyond
`pilot-agent`, so the curl tests below bring their own image. Any image with curl works;
`registry.access.redhat.com/ubi9/ubi` is one. Use your mirror if the cluster can't pull from
there.

## Redirect check: `got 502`

**Symptom.** `gateway-redirect` fails with `got 502`, while `curl -I http://<hostname>/` from
outside the cluster gets `301` with an `https://` location.

**What the check does.** It sends `GET http://<gateway.hostname>/public` to `gateway.address`
(default `<gateway.name>-istio.<gateway.namespace>.svc`) on `gateway.httpPort`, without
following redirects, and passes only on exactly `301` with a `Location` starting `https://`.

**Cause.** The console's sidecar intercepts that plain-HTTP request. Istio's gateway pods are
labelled mTLS-capable, so the sidecar sends the request to the gateway wrapped in mesh mTLS.
The gateway's port-80 listener expects plain HTTP, rejects it, and the sidecar answers `502`.
An outside client has no sidecar, so it gets the `301`.

**Confirm.**

```sh
# The sidecar logs the 502, with a response flag such as UC, UF or URX
kubectl logs -n <ns> <console-pod> -c istio-proxy | grep ' 502 '
```

The response also carries `server: envoy` and a body like
`upstream connect error or disconnect/reset before headers`.

**Fix.** The chart renders a DestinationRule, `<release>-gateway-http`, that turns mesh TLS off
for the gateway Service's HTTP port, for clients in the release namespace only
(`templates/mesh.yaml`). Upgrade to a chart version that has it.

- It is not rendered when `gateway.address` is an IP address, because a DestinationRule host
  can't be one. Use a hostname there.
- With `gateway.address` empty, the host is `<name>-istio.<namespace>.svc.cluster.local`. If
  your cluster's DNS domain isn't `cluster.local`, set `gateway.address` to the full name.

Other things that also fail this check:

| Detail | Meaning |
|---|---|
| `got error: …` | Nothing answered on `gateway.address`:`gateway.httpPort` |
| `got 404` or `got 200` | A listener answered, but no redirect route matches the probe's hostname or `/public` |
| `got 302 https://…` (or 307, 308) | The redirect works, but the check accepts only 301 |

## OIDC: `discovery: error: … connection reset by peer`

**Symptom.** The OIDC checks fail fetching
`<issuerUrl>/.well-known/openid-configuration` with `connection reset by peer`, while the URL
works from elsewhere.

**What the probe does.** It fetches the discovery document, then the token, with the console's
mesh HTTP client. That traffic goes through the sidecar. With `registryOnly` on, the chart adds
a ServiceEntry for the issuer's host, HTTPS on port 443 only.

**Find which side resets it.** Run the same request once without the sidecar and once through
it.

A. Without the sidecar, from a throwaway pod:

```sh
kubectl run kc-test -n <ns> --rm -it --restart=Never \
  --image=registry.access.redhat.com/ubi9/ubi \
  --labels=sidecar.istio.io/inject=false \
  --overrides='{"metadata":{"annotations":{"sidecar.istio.io/inject":"false"}}}' \
  -- curl -sv https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration
```

B. Through the console's sidecar. The debug container shares the pod's network, so its traffic
takes the probe's path:

```sh
kubectl debug -n <ns> -it <console-pod> \
  --image=registry.access.redhat.com/ubi9/ubi \
  -- curl -sv https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration
```

### A is reset too: the network needs an egress proxy

The cluster can't connect to Keycloak directly, and your other clients reach it through a
proxy. On OpenShift:

```sh
oc get proxy cluster -o jsonpath='{.spec.httpsProxy}'
```

The probe's mesh client doesn't read `HTTPS_PROXY`/`NO_PROXY` yet, so it always connects
directly. That needs a code change. Once it does, the proxy's host must also be in
`mesh.egress.allowedHosts`.

### A works, B is reset: the sidecar drops or breaks the connection

```sh
# Does the sidecar have healthy endpoints for Keycloak? Empty means no ServiceEntry
# applies, or the sidecar can't resolve the name.
kubectl exec -n <ns> <console-pod> -c istio-proxy -- \
  pilot-agent request GET clusters | grep <keycloak-host>

# Rising counters here mean the sidecar treats the host as unknown and drops it
kubectl exec -n <ns> <console-pod> -c istio-proxy -- \
  pilot-agent request GET stats | grep BlackHoleCluster

# A mesh-wide DestinationRule forcing ISTIO_MUTUAL (e.g. host "*") wraps the
# connection to Keycloak in mesh mTLS, which Keycloak resets
kubectl get destinationrule -A -o yaml | grep -B5 -A5 ISTIO_MUTUAL
```

Also look for another ServiceEntry for the same host in another namespace, which can conflict
with the chart's:

```sh
kubectl get serviceentry -A -o yaml | grep -B10 <keycloak-host>
```

The chart's ServiceEntry assumes HTTPS on 443. An issuer on another port, on plain `http://`,
or on an in-cluster Service is dropped the same way.

### Unblock in the meantime

Setting `mesh.egress.registryOnly: false` removes the egress restriction. If the OIDC checks
then pass, the cause is on the sidecar side (case B). The egress check is skipped while it's
off.
