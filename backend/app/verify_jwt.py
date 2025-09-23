#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Simple JWT verifier for ConfMgr.
# - Supports HS256 (shared secret) and RS256/ES256 (public key).
# - Reads defaults from ENV: JWT_ALG, JWT_SIGNING_KEY (HS), JWT_PUBLIC_KEY (RS/ES),
#   ISSUER (iss), JWT_AUDIENCE (aud).
# - You can also pass values via CLI flags to override ENV.
#
# Exit codes:
#   0  - token is valid
#   1  - token is invalid / verification failed
#
# Usage examples:
#   export JWT_SIGNING_KEY="supersecret" JWT_ALG=HS256 ISSUER="confmgr-9834df80" JWT_AUDIENCE="confmgr"
#   ./verify_jwt.py --token "$TOKEN"
#
#   # RS256 example:
#   export JWT_PUBLIC_KEY=/path/to/jwt_pub.pem JWT_ALG=RS256 ISSUER="confmgr-9834df80" JWT_AUDIENCE="confmgr"
#   ./verify_jwt.py --token "$TOKEN"

import os
import sys
import json
import argparse
from typing import Optional
import jwt  # PyJWT

def read_key_material(value_or_path: Optional[str]) -> Optional[str]:
    """If the value looks like a file path and exists, read file; otherwise return the string as-is."""
    if not value_or_path:
        return None
    try:
        if os.path.exists(value_or_path):
            with open(value_or_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception:
        # Fall back to treating as literal key if file read fails
        pass
    return value_or_path

def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a JWT (signature + iss/aud/exp).")
    parser.add_argument("--token", "-t", help="JWT string; if omitted, read from STDIN", default=None)
    parser.add_argument("--alg", help="Algorithm (HS256/RS256/ES256). Default from $JWT_ALG or HS256.",
                        default=os.getenv("JWT_ALG", "HS256"))
    parser.add_argument("--iss", help="Expected issuer (iss). Default from $ISSUER.",
                        default=os.getenv("ISSUER"))
    parser.add_argument("--aud", help="Expected audience (aud). Default from $JWT_AUDIENCE.",
                        default=os.getenv("JWT_AUDIENCE"))
    # Key options
    parser.add_argument("--key", help="Signing key (HS) or PUBLIC key (RS/ES). Overrides ENV.", default=None)
    parser.add_argument("--key-file", help="Path to key file. Overrides --key.", default=None)
    # ENV fallbacks:
    #  - HS256: JWT_SIGNING_KEY (raw string)
    #  - RS/ES: JWT_PUBLIC_KEY (PEM string or path)
    args = parser.parse_args()

    token = args.token or sys.stdin.read().strip()
    if not token:
        print("ERR: no token provided (use --token or pipe via STDIN)", file=sys.stderr)
        return 1

    alg = args.alg.upper().strip()
    if alg not in ("HS256", "RS256", "ES256"):
        print(f"ERR: unsupported alg '{alg}' (use HS256/RS256/ES256)", file=sys.stderr)
        return 1

    # Resolve key material
    key_material = None
    if args.key_file:
        key_material = read_key_material(args.key_file)
    elif args.key:
        key_material = args.key
    else:
        if alg == "HS256":
            key_material = os.getenv("JWT_SIGNING_KEY")
        else:
            key_material = os.getenv("JWT_PUBLIC_KEY")
        key_material = read_key_material(key_material)

    if not key_material:
        need = "JWT_SIGNING_KEY" if alg == "HS256" else "JWT_PUBLIC_KEY"
        print(f"ERR: no key material. Provide --key/--key-file or set ${need}", file=sys.stderr)
        return 1

    # Build verification options
    verify_opts = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_aud": args.aud is not None,
        "verify_iss": args.iss is not None,
    }

    try:
        # Decode (verify) token
        claims = jwt.decode(
            token,
            key_material,
            algorithms=[alg],
            audience=args.aud,
            issuer=args.iss,
            options=verify_opts,
        )
        # Also show JOSE header (e.g. kid)
        header = jwt.get_unverified_header(token)

        print("VALID")
        print("--- header ---")
        print(json.dumps(header, indent=2, ensure_ascii=False))
        print("--- claims ---")
        print(json.dumps(claims, indent=2, ensure_ascii=False))
        # Convenience: show principal fields if present
        aid = claims.get("aid") or claims.get("actor_id")
        asub = claims.get("asub") or claims.get("actor_subject")
        cid = claims.get("cid") or claims.get("client_id")
        scope = claims.get("scope")
        summary = {
            "principal_id": aid,
            "principal_subject": asub,
            "client_id": cid,
            "scope": scope,
        }
        print("--- principal ---")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    except jwt.ExpiredSignatureError:
        print("INVALID: token expired", file=sys.stderr)
    except jwt.InvalidAudienceError:
        print("INVALID: audience (aud) mismatch", file=sys.stderr)
    except jwt.InvalidIssuerError:
        print("INVALID: issuer (iss) mismatch", file=sys.stderr)
    except jwt.InvalidSignatureError:
        print("INVALID: signature verification failed", file=sys.stderr)
    except jwt.PyJWTError as e:
        print(f"INVALID: {e}", file=sys.stderr)
    return 1

if __name__ == "__main__":
    sys.exit(main())
