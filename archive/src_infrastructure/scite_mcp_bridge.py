#!/usr/bin/env python3
"""
Stdio-to-HTTP MCP Bridge for scite.ai
Maintains session state and proxies MCP JSON-RPC messages between stdio and https://api.scite.ai/mcp.
"""
import os
import sys
import json
import urllib.request

URL = "https://api.scite.ai/mcp"
session_id = None
api_key = os.getenv("SCITE_API_KEY") or os.getenv("SCITE_TOKEN")

def main():
    global session_id
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req_data = line.encode('utf-8')
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            if session_id:
                headers["mcp-session-id"] = session_id
            
            http_req = urllib.request.Request(URL, data=req_data, headers=headers)
            with urllib.request.urlopen(http_req, timeout=30) as resp:
                resp_headers = dict(resp.getheaders())
                new_session = resp_headers.get('mcp-session-id') or resp_headers.get('Mcp-Session-Id')
                if new_session:
                    session_id = new_session
                resp_body = resp.read().decode('utf-8')
                sys.stdout.write(resp_body + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Bridge error: {str(e)}"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
