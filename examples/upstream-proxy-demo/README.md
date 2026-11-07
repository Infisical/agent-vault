# Upstream proxy demo

A self-contained, offline end-to-end walkthrough of [upstream proxies](../../docs/learn/upstream-proxies.mdx). It runs a stand-in upstream API on IPv4 and IPv6 loopback, a logging egress proxy, and the Agent Vault broker. The two target listeners let the demo use a valid path-scoped service hostname (`localhost.localdomain`) even when it resolves to `::1` first.

No external network is used. The broker has an isolated `HOME` (fresh SQLite database and CA) in a temporary directory; all demo listeners run on loopback and stop on exit. Logs remain in that temporary directory; temporary bearer-token files are deleted on exit.

## What it proves

| Step | Assertion |
| --- | --- |
| 5 | With no profile, brokered requests dial the target directly. |
| 5a | A non-default profile carries only `/opt-in` on `localhost.localdomain`; `/opt-out` and unmatched `/unmatched` on the **same host** dial directly. Target and proxy logs prove each route. |
| 6 | Promoting the profile to instance default routes otherwise-unmatched requests through the proxy. |
| 6a | With that default enabled, a newly created service without egress fields dials directly; `use_upstream_proxy: true` opts another service into the instance default, while a named-profile service and unmatched requests also use the proxy. Conflicting egress settings return `400` without changing the route. |
| 7 | `no_proxy` lets a matching target bypass the proxy again. |
| 8 | `fail_closed` refuses the request (502) when the proxy is unreachable — no silent fallback. |
| 9 | `fail_open` lets that request through by dialling directly. |
| 10 | Services reference profiles by name; unknown names are rejected, and a referenced profile cannot be deleted. Select Direct explicitly before deleting the profile: omitting the egress fields on an update retains the existing choice. |

The evidence is the proxy's own request log and the target request log: only `/opt-in` appears at the proxy in step 5a; `/opt-out` and `/unmatched` reach the target without touching it. In step 6a, a new service without egress fields reaches the target directly, while `/default-opt-in`, the named-profile path, and unmatched requests appear at the proxy. Existing services that inherited the default before this change retain their routing; newly created services are direct unless opted in.

## Requirements

- Go 1.25+ (or an `agent-vault` binary already on `PATH`)
- Python 3 (standard library only)
- `curl`

## Run

```bash
cd examples/upstream-proxy-demo
./run.sh
```

Ports used: `14331` (control plane), `14332` (MITM proxy), `13128` (demo egress proxy), `18099` (demo target on `127.0.0.1` and `::1`). All background processes are stopped on exit. IPv6 loopback and `localhost.localdomain` resolving to loopback are required for the path-scoped service fixture.

## Expected output

<details open>
<summary>Full run (abbreviated paths)</summary>

```
0. Building the broker
  ✓ using broker binary (...)

1. Starting a stand-in upstream target on 127.0.0.1:18099
  ✓ target serves GET / (200)

2. Starting the logging egress proxy on 127.0.0.1:13128
  ✓ proxy forwards requests and logs them to egress-proxy.log

3. Starting the broker (ports 14331 / 14332)
  ✓ broker ready (isolated HOME=/tmp/tmp.XXXXXXXX)

4. Registering the owner and minting an agent token
  ✓ owner registered (first user becomes instance owner)
  ✓ vault-scoped agent token minted

5. Baseline: with no profile, requests dial the target directly
  ✓ brokered request reached target directly (200)

5a. Non-default profile: only a selected endpoint uses the proxy
  ✓ selected path proxied; unselected service and unmatched path direct

6. Promoting 'corp-egress' to the instance default
  ✓ default fail_closed profile enabled
  ✓ request transited proxy and reached target (200)

6a. New service direct by default with the instance default enabled
  ✓ new service direct; default opt-in, named, and unmatched paths proxied
  ✓ conflicting settings rejected (400), existing direct route unchanged

7. no_proxy lets a target bypass the profile
  ✓ request reached target without proxy

8. fail_closed when the proxy is unreachable
  ✓ proxy down: 502, target untouched

9. fail_open lets the same request through
  ✓ request reached target directly after proxy refused connection

10. Services reference profiles by name
  ✓ unknown profile reference rejected (400)
  ✓ service references profile
  ✓ referenced profile delete refused (409)
  ✓ unreferenced profile deleted
```

</details>

Each step fails the script loudly (`✗`) rather than continuing past a broken assumption. The final output prints the log directory — `broker.log`, `egress-proxy.log`, and `target.log` are the useful files.

## Files

| File | Purpose |
| --- | --- |
| `run.sh` | Orchestrates the whole flow: build, four processes, opt-in and default routing, cleanup. |
| `egress_proxy.py` | ~150-line logging HTTP proxy. Understands absolute-form requests and `CONNECT`, forwards them, and appends one line per request to its log file — the demo's source of truth. |

## Notes for adapting this to a real proxy

- `AGENT_VAULT_ALLOW_PRIVATE_RANGES=true` and `AGENT_VAULT_DEV_MODE=true` apply only to the isolated broker process because this fixture targets loopback and uses a local service hostname. A real deployment needs neither: leave private-range and internal-host protections on.
- Replace `egress_proxy.py` with your real proxy and set `scheme`/`host` to it; if it terminates TLS with a private CA, paste that certificate into the profile's **CA certificate (PEM)** field.
- Steps 8 and 9 are the ones worth rehearsing before a cutover: stop the proxy, confirm the broker's behaviour under `fail_closed`, then decide whether `fail_open` is acceptable for that window.
