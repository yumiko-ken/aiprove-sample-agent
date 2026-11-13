#!/usr/bin/env python3
"""A minimal sample agent for the AIProve bounty arena (aiprove.fun).

Implements exactly the loop described in https://aiprove.fun/skill.md:

    generate/load a keypair -> authenticate (challenge, EIP-191 sign,
    verify) -> list open bounties -> enter one.

Identity is the keypair: there is no signup, no account, no email. The
private key lives in a local file (created with mode 0600 if missing) and
is never printed.

Usage:
    python3 agent.py                        # list open bounties, enter the first
    python3 agent.py --enter forecast-btc-7d
    python3 agent.py --list-only            # authenticate + list, do not enter

Environment:
    API_BASE_URL    default https://aiprove.fun
    AGENT_KEY_FILE  default ./agent.key next to this script
    AGENT_HANDLE    optional public handle to attach to the entry

Dependencies: eth-account (see requirements.txt). Everything else is the
Python standard library (urllib for HTTP).
"""
import argparse
import gzip
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request

from eth_account import Account
from eth_account.messages import encode_defunct

API_BASE = os.environ.get("API_BASE_URL", "https://aiprove.fun").rstrip("/")
KEY_FILE = os.environ.get(
    "AGENT_KEY_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.key"),
)
# The API sits behind Cloudflare, which rejects the default urllib
# user-agent; present as a browser-like client.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) aiprove-sample-agent/1.0"


def api(method, path, body=None, token=None, attempts=3):
    """One JSON HTTP call against the arena API.

    Retries a few times on transient transport failures (the edge in front
    of the API occasionally drops or truncates urllib connections) and on
    502/503/504. Real API errors (4xx) raise immediately.
    """
    data = json.dumps(body).encode() if body is not None else None
    last_exc = None
    for attempt in range(attempts):
        req = urllib.request.Request(API_BASE + path, data=data, method=method)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Content-Type", "application/json")
        # gzip shrinks the ~15 KB bounty list to ~4 KB on the wire, which
        # also makes mid-body connection drops far less likely.
        req.add_header("Accept-Encoding", "gzip")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return json.loads(raw.decode())
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504) and attempt < attempts - 1:
                last_exc = e
            else:
                raise RuntimeError(f"{method} {path} -> HTTP {e.code}: "
                                   f"{e.read().decode(errors='replace')[:200]}") from e
        except (urllib.error.URLError, http.client.HTTPException,
                ConnectionError, TimeoutError) as e:
            last_exc = e
        time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{method} {path} failed after {attempts} attempts: {last_exc}")


def load_or_create_account():
    """Load the agent keypair from KEY_FILE, or generate and save a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            return Account.from_key(f.read().strip())
    acct = Account.create()
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(acct.key.hex())
    return acct


def authenticate(acct):
    """Keypair challenge -> EIP-191 sign -> session token (skill.md step 1)."""
    for handshake in range(2):
        challenge = api("GET", f"/api/auth/challenge?address={acct.address}")["challenge"]
        signature = acct.sign_message(encode_defunct(text=challenge)).signature.hex()
        # eth-account's .hex() returns the bare 130 hex chars; the API expects
        # the 0x-prefixed form (as ethers' signMessage returns). Without the
        # prefix the server answers 401 "malformed signature".
        if not signature.startswith("0x"):
            signature = "0x" + signature
        try:
            session = api("POST", "/api/auth/verify",
                          {"address": acct.address, "signature": signature})
            return session["token"]
        except RuntimeError as e:
            # A challenge is single-use; if a dropped connection made the
            # server consume/supersede it before verify landed, it answers
            # "no active challenge" — just redo the handshake once with a
            # fresh challenge.
            if "no active challenge" in str(e) and handshake == 0:
                continue
            raise


def list_open_bounties():
    """Open bounties (skill.md step 2). Public endpoint, no auth needed."""
    return api("GET", "/api/bounties?status=open")["bounties"]


def enter_bounty(token, slug, handle=None):
    """Enter one bounty (free; skill.md step 3).

    Entering is idempotent on the server side: a second enter for the
    same agent is answered 409 "already entered". That matters because a
    retried POST can land twice when a connection drops after the server
    processed the first attempt — so 409 is treated as success here.
    """
    body = {"handle": handle} if handle else {}
    try:
        return api("POST", f"/api/bounties/{slug}/enter", body, token=token)
    except RuntimeError as e:
        if "already entered" in str(e):
            return {"id": None, "bountySlug": slug, "note": "already entered"}
        raise


def main():
    ap = argparse.ArgumentParser(description="Minimal AIProve sample agent")
    ap.add_argument("--enter", metavar="SLUG",
                    help="bounty slug to enter (default: first open bounty)")
    ap.add_argument("--list-only", action="store_true",
                    help="authenticate and list, but do not enter anything")
    ap.add_argument("--handle", default=os.environ.get("AGENT_HANDLE"),
                    help="optional public handle for the entry")
    args = ap.parse_args()

    acct = load_or_create_account()
    print(f"agent address: {acct.address}")

    token = authenticate(acct)
    print("authenticated: session token received (value not printed)")

    bounties = list_open_bounties()
    print(f"open bounties: {len(bounties)}")
    for b in bounties:
        print(f"  - {b['slug']:<24} {b['amt']} {b['unit']:<6} lane={b['lane']:<11} closes={b['closes']}")

    if args.list_only:
        print("list-only mode: not entering anything")
        return 0

    slug = args.enter or (bounties[0]["slug"] if bounties else None)
    if not slug:
        print("no open bounties to enter")
        return 1
    entry = enter_bounty(token, slug, args.handle)
    if entry.get("note") == "already entered":
        print(f"entered: {slug}  (this agent had already entered; entry exists)")
    else:
        print(f"entered: {slug}  entry id={entry.get('id')}  agent={entry.get('agent')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
