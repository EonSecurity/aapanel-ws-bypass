#!/usr/bin/env python3
"""
aaPanel WebSocket Vulnerability Checker
Detects if an aaPanel instance has vulnerable WebSocket endpoints.

Safe to run — does not execute commands or modify state.
"""

import argparse
import json
import ssl
import sys
import asyncio


async def check_endpoint(target, endpoint, use_ssl=True):
    """Check if a WebSocket endpoint accepts connections and responds."""
    import websockets
    
    protocol = "wss" if use_ssl else "ws"
    uri = f"{protocol}://{target}{endpoint}"
    
    ssl_context = None
    if use_ssl:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        async with websockets.connect(uri, ssl=ssl_context, close_timeout=5) as ws:
            # Send CSRF bypass
            await ws.send(json.dumps({"x-http-token": ""}))
            
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                if "token error" in resp:
                    return "PROTECTED (CSRF check active)"
                elif "302" in resp or "FOUND" in resp:
                    return "AUTH REQUIRED (needs valid session)"
                else:
                    return f"VULNERABLE? (response: {resp[:50]})"
            except asyncio.TimeoutError:
                return "VULNERABLE (no response — possible bypass)"
    except Exception as e:
        return f"ERROR ({str(e)[:60]})"


async def main():
    parser = argparse.ArgumentParser(description="Check aaPanel for WebSocket vulnerabilities")
    parser.add_argument("target", help="aaPanel host:port (e.g. 192.168.1.100:8888)")
    parser.add_argument("--no-ssl", action="store_true", help="Use ws:// instead of wss://")
    args = parser.parse_args()
    
    endpoints = [
        "/webssh",
        "/sock_shell",
        "/ws_panel",
        "/ws_home",
        "/ws_project",
        "/ws_model",
        "/workorder_client",
    ]
    
    use_ssl = not args.no_ssl
    protocol = "wss" if use_ssl else "ws"
    
    print(f"aaPanel WebSocket Vulnerability Checker")
    print(f"Target: {protocol}://{args.target}")
    print(f"Endpoints to check: {len(endpoints)}")
    print()
    
    for ep in endpoints:
        result = await check_endpoint(args.target, ep, use_ssl)
        status = "✓" if "PROTECTED" in result else "!" if "VULNERABLE" in result else "?"
        print(f"  [{status}] {ep:25s} → {result}")
    
    print()
    print("NOTE: This check does NOT require authentication.")
    print("If any endpoint shows VULNERABLE, the CSRF bypass works.")
    print("Full RCE requires a valid session (logged-in admin).")


if __name__ == "__main__":
    asyncio.run(main())
