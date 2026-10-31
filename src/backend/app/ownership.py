"""Real setup ownership verification.

Supported proofs:
  * HTTP challenge: exact token read from a fixed well-known path on the target.
  * SSH: authenticate to the target and either read the challenge file or prove
    effective root/passwordless sudo.
  * Database: connect with PostgreSQL/MySQL credentials and either read the
    challenge row using a parameterized query or verify an administrative role.

Credential values are request-scoped only. This module returns an attestation;
it never returns or stores passwords, private keys, or connection strings.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import ipaddress
import os
import socket
import time
from urllib.parse import urlparse

import httpx

HTTP_PATH = "/.well-known/sentinel-apex-verification.txt"
SSH_PATH = "/etc/sentinel-apex/verification.txt"
DB_TABLE = "sentinel_verify"


class VerificationError(ValueError):
    pass


def normalize_target(raw: str) -> dict:
    value = (raw or "").strip()
    if not value:
        raise VerificationError("Monitoring target is required.")
    if "://" not in value:
        value = "https://" + value
    try:
        u = urlparse(value)
    except Exception as exc:
        raise VerificationError("Monitoring target is not a valid URL or host.") from exc
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise VerificationError("Target must be an http(s) URL/host without embedded credentials.")
    host = u.hostname.rstrip(".").lower()
    allow_loopback = os.getenv("SENTINEL_ALLOW_LOOPBACK_TARGETS", "false").lower() == "true"
    if not allow_loopback:
        is_loopback = host == "localhost"
        try: is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
        except ValueError: pass
        if is_loopback:
            raise VerificationError("Loopback targets are disabled for real monitoring. Set SENTINEL_ALLOW_LOOPBACK_TARGETS=true only in an isolated local-development environment.")
    port = u.port
    origin = f"{u.scheme}://{host}" + (f":{port}" if port else "")
    return {"input": raw, "origin": origin, "host": host, "scheme": u.scheme, "port": port}


def challenge_locations(target: dict) -> dict:
    return {
        "http_url": target["origin"] + HTTP_PATH,
        "ssh_path": SSH_PATH,
        "database": {
            "table": DB_TABLE,
            "create_sql": "CREATE TABLE IF NOT EXISTS sentinel_verify (token TEXT PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "insert_sql": "INSERT INTO sentinel_verify(token) VALUES ('<TOKEN>');",
        },
    }


def digest(value: str) -> str:
    return hashlib.sha256((value or "").strip().encode("utf-8")).hexdigest()


async def verify(challenge: dict, proof: dict) -> dict:
    method = str(proof.get("method") or "").lower()
    if method == "http_token":
        return await _verify_http(challenge)
    if method in ("ssh_token", "ssh_privileged"):
        return await asyncio.to_thread(_verify_ssh, challenge, proof, method)
    if method in ("database_token", "database_privileged"):
        return await asyncio.to_thread(_verify_database, challenge, proof, method)
    raise VerificationError("Choose HTTP token, SSH, or database ownership proof.")


async def _verify_http(challenge: dict) -> dict:
    target = normalize_target(challenge["target"])
    # Permit private/loopback targets for self-hosted deployments, but never let
    # this verifier reach link-local metadata, multicast, or unspecified space.
    try:
        addresses = {row[4][0] for row in await asyncio.to_thread(socket.getaddrinfo, target["host"], target.get("port") or 80)}
        for raw in addresses:
            ip = ipaddress.ip_address(raw)
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise VerificationError("Verification target resolves to a prohibited link-local/multicast address.")
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("Could not resolve the declared verification target.") from exc
    url = target["origin"] + HTTP_PATH
    # Redirects are intentionally disabled: a token on a different origin does
    # not prove control of the declared target.
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False,
                                     headers={"User-Agent": "SENTINEL-APEX-Ownership/1.0"}) as client:
            r = await client.get(url)
    except Exception as exc:
        raise VerificationError("Could not read the verification file from the declared target.") from exc
    if r.status_code != 200:
        raise VerificationError(f"Verification URL returned HTTP {r.status_code}; expected 200.")
    if len(r.content) > 4096:
        raise VerificationError("Verification response is too large.")
    if digest(r.text) != challenge["token_hash"]:
        raise VerificationError("Verification URL content does not match the active one-time token.")
    return _attestation("http_token", target["host"], "well-known token readback")


def _load_private_key(value: str):
    import paramiko
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(value))
        except Exception as exc:
            last = exc
    raise VerificationError("The supplied SSH private key format is not supported.") from last


def _verify_ssh(challenge: dict, proof: dict, method: str) -> dict:
    try:
        import paramiko
    except ImportError as exc:
        raise VerificationError("SSH verification dependency is not installed.") from exc
    target = normalize_target(challenge["target"])
    host = str(proof.get("host") or target["host"]).strip()
    if host.rstrip(".").lower() != target["host"]:
        raise VerificationError("SSH host must match the declared monitoring target.")
    username = str(proof.get("username") or "").strip()
    if not username:
        raise VerificationError("SSH username is required.")
    password = proof.get("password") or None
    key_text = proof.get("private_key") or None
    if not password and not key_text:
        raise VerificationError("Supply an SSH password or private key.")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if proof.get("trust_on_first_use") else paramiko.RejectPolicy())
    try:
        pkey = _load_private_key(key_text) if key_text else None
        client.connect(hostname=host, port=int(proof.get("port") or 22), username=username,
                       password=password, pkey=pkey, timeout=10, banner_timeout=10,
                       auth_timeout=10, look_for_keys=False, allow_agent=False)
        expected_fp = str(proof.get("host_key_sha256") or "").strip().removeprefix("SHA256:")
        remote_key = client.get_transport().get_remote_server_key()
        observed_fp = base64.b64encode(hashlib.sha256(remote_key.asbytes()).digest()).decode().rstrip("=")
        if expected_fp and expected_fp != observed_fp:
            raise VerificationError("SSH host-key fingerprint mismatch.")

        if method == "ssh_token":
            with client.open_sftp().open(SSH_PATH, "r") as fh:
                content = fh.read(4097)
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="strict")
            if len(content) > 4096 or digest(content) != challenge["token_hash"]:
                raise VerificationError("SSH verification file does not match the active one-time token.")
            privilege = "token file readback"
        else:
            _, stdout, _ = client.exec_command("id -u", timeout=6)
            uid = stdout.read(64).decode(errors="ignore").strip()
            if uid != "0":
                _, stdout, _ = client.exec_command("sudo -n id -u", timeout=6)
                uid = stdout.read(64).decode(errors="ignore").strip()
            if uid != "0":
                raise VerificationError("SSH login succeeded but root/passwordless-sudo privilege was not verified.")
            privilege = "effective root/sudo"
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("SSH authentication or ownership verification failed.") from exc
    finally:
        client.close()
    return _attestation(method, host, privilege, {"host_key_sha256": "SHA256:" + observed_fp})


def _verify_database(challenge: dict, proof: dict, method: str) -> dict:
    engine = str(proof.get("engine") or "postgresql").lower()
    target = normalize_target(challenge["target"])
    host = str(proof.get("host") or "").strip()
    username = str(proof.get("username") or "").strip()
    password = proof.get("password") or ""
    database = str(proof.get("database") or "").strip()
    if not host or not username or not database:
        raise VerificationError("Database host, database, and username are required.")
    if engine in ("postgres", "postgresql"):
        return _verify_postgres(challenge, proof, method, host, username, password, database, target)
    if engine in ("mysql", "mariadb"):
        return _verify_mysql(challenge, proof, method, host, username, password, database, target)
    raise VerificationError("Supported database engines: PostgreSQL and MySQL/MariaDB.")


def _verify_postgres(challenge, proof, method, host, username, password, database, target):
    try:
        import psycopg
        with psycopg.connect(host=host, port=int(proof.get("port") or 5432), dbname=database,
                             user=username, password=password, connect_timeout=10,
                             sslmode=str(proof.get("sslmode") or "prefer")) as conn:
            with conn.cursor() as cur:
                if method == "database_token":
                    cur.execute("SELECT token FROM sentinel_verify WHERE token = %s LIMIT 1", (proof.get("token") or "",))
                    row = cur.fetchone()
                    if not row or digest(str(row[0])) != challenge["token_hash"]:
                        raise VerificationError("Database challenge row does not match the active one-time token.")
                    privilege = "database token-row readback"
                else:
                    cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                    row = cur.fetchone()
                    if not row or row[0] is not True:
                        raise VerificationError("Database login succeeded but PostgreSQL superuser privilege was not verified.")
                    privilege = "PostgreSQL superuser"
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("PostgreSQL authentication or ownership verification failed.") from exc
    return _attestation(method, target["host"], privilege, {"database_engine": "postgresql", "database_host": host})


def _verify_mysql(challenge, proof, method, host, username, password, database, target):
    try:
        import pymysql
        conn = pymysql.connect(host=host, port=int(proof.get("port") or 3306), user=username,
                               password=password, database=database, connect_timeout=10,
                               read_timeout=10, write_timeout=10, ssl={"check_hostname": True} if proof.get("ssl") else None)
        try:
            with conn.cursor() as cur:
                if method == "database_token":
                    cur.execute("SELECT token FROM sentinel_verify WHERE token = %s LIMIT 1", (proof.get("token") or "",))
                    row = cur.fetchone()
                    if not row or digest(str(row[0])) != challenge["token_hash"]:
                        raise VerificationError("Database challenge row does not match the active one-time token.")
                    privilege = "database token-row readback"
                else:
                    cur.execute("SHOW GRANTS FOR CURRENT_USER")
                    grants = " ".join(str(r[0]) for r in cur.fetchall()).upper()
                    if not any(x in grants for x in ("ALL PRIVILEGES", "SYSTEM_USER", "SUPER")):
                        raise VerificationError("Database login succeeded but MySQL administrative privilege was not verified.")
                    privilege = "MySQL administrative grant"
        finally:
            conn.close()
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("MySQL authentication or ownership verification failed.") from exc
    return _attestation(method, target["host"], privilege, {"database_engine": "mysql", "database_host": host})


def _attestation(method: str, target: str, privilege: str, extra: dict | None = None) -> dict:
    out = {
        "verified": True,
        "method": method,
        "target": target,
        "privilege": privilege,
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verifier": "sentinel-apex/ownership-v1",
        "credentials_stored": False,
    }
    out.update(extra or {})
    return out
