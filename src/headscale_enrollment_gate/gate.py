"""Local, durable admission checks before issuing Headscale auth keys.

This module calls the unmodified Headscale CLI. It does not replace Headscale's
registration or claim that a pre-auth key identifies a particular device.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol


TAG = re.compile(r"tag:[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
USER_ID = re.compile(r"[1-9][0-9]*\Z")


class GateError(Exception):
    """A closed admission decision safe to show to the caller."""


def canonical_tags(tags: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if len(tags) != len(set(tags)) or any(not TAG.fullmatch(tag) for tag in tags):
        raise GateError("invalid or repeated tag")
    return tuple(sorted(tags))


@dataclass(frozen=True)
class MintedKey:
    secret: str
    key_id: str
    user_id: str
    tags: tuple[str, ...]
    expires_at: float
    reusable: bool
    used: bool


class KeyIssuer(Protocol):
    def mint(self, user_id: str, tags: tuple[str, ...], ttl_seconds: int) -> MintedKey: ...

    def expire(self, key_id: str) -> None: ...


class HeadscaleCLI:
    """Adapter for a trusted local Headscale control socket."""

    def __init__(self, binary: Path, config: Path, timeout: float = 20.0):
        self.binary, self.config, self.timeout = binary, config, timeout

    def _run(self, args: list[str]) -> dict:
        try:
            result = subprocess.run(
                [str(self.binary), "-c", str(self.config), "-o", "json", *args],
                check=False,
                capture_output=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateError("Headscale request failed") from exc
        if result.returncode:
            # Headscale output may contain credential material. Never echo it.
            raise GateError("Headscale request rejected")
        try:
            value = json.loads(result.stdout)
        except (UnicodeError, ValueError) as exc:
            raise GateError("Headscale response was invalid") from exc
        if not isinstance(value, dict):
            raise GateError("Headscale response was invalid")
        return value

    def mint(self, user_id: str, tags: tuple[str, ...], ttl_seconds: int) -> MintedKey:
        args = [
            "preauthkeys", "create", "--user", user_id,
            "--expiration", f"{ttl_seconds}s",
        ]
        for tag in tags:
            args.extend(("--tags", tag))
        value = self._run(args)
        key_id = value.get("id")
        try:
            expiry = datetime.fromisoformat(value["expiration"].replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("timezone is required")
            secret = value["key"]
            key_id = value["id"]
            actual_user = value["user"]["id"]
            actual_tags = canonical_tags(value["aclTags"])
            if not isinstance(secret, str) or not secret.startswith("hskey-auth-"):
                raise ValueError("bad secret")
            if not isinstance(key_id, str) or not USER_ID.fullmatch(key_id):
                raise ValueError("bad id")
            if not isinstance(actual_user, str):
                raise ValueError("bad user")
            return MintedKey(
                secret=secret,
                key_id=key_id,
                user_id=actual_user,
                tags=actual_tags,
                expires_at=expiry.timestamp(),
                reusable=value["reusable"],
                used=value["used"],
            )
        except (AttributeError, KeyError, TypeError, ValueError, GateError) as exc:
            if isinstance(key_id, str) and USER_ID.fullmatch(key_id):
                try:
                    self.expire(key_id)
                except GateError:
                    pass
            raise GateError("Headscale key metadata was invalid") from exc

    def expire(self, key_id: str) -> None:
        self._run(["preauthkeys", "expire", "--id", key_id])


class EnrollmentGate:
    """An operator-side one-time grant, backed by SQLite on local storage."""

    def __init__(
        self,
        db_path: Path,
        policy_path: Path,
        issuer: KeyIssuer,
        clock: Callable[[], float] = time.time,
    ):
        self.db_path, self.policy_path, self.issuer, self.clock = (
            db_path, policy_path, issuer, clock
        )
        db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if db_path.is_symlink():
            raise GateError("database path must not be a symlink")
        old_mask = os.umask(0o077)
        try:
            with self._connect() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT UNIQUE NOT NULL,
                    audience TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    key_id TEXT,
                    issued_at REAL
                )""")
                db.execute("""CREATE TABLE IF NOT EXISTS clock_state (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    last_time REAL NOT NULL
                )""")
                db.execute(
                    "INSERT OR IGNORE INTO clock_state(id,last_time) VALUES (1,0)"
                )
        finally:
            os.umask(old_mask)
        if db_path.stat().st_mode & 0o077:
            raise GateError("database permissions are too broad")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("PRAGMA journal_mode=WAL")
            yield db
        finally:
            db.close()

    def _allowed(
        self, audience: str, mode: str, user_id: str, tags: tuple[str, ...]
    ) -> bool:
        try:
            policy = json.loads(self.policy_path.read_text())
            if policy["version"] != 1 or not isinstance(policy["audiences"], dict):
                return False
            role = policy["audiences"][audience]
            if mode == "personal":
                return not tags and user_id in role["personal_users"]
            if mode == "tagged":
                allowed = role["tagged"][user_id]
                return bool(tags) and set(tags).issubset(set(allowed))
            return False
        except (OSError, UnicodeError, ValueError, KeyError, TypeError):
            return False

    def _observe_clock(self, db: sqlite3.Connection) -> float:
        now = float(self.clock())
        if not math.isfinite(now) or now < 0:
            raise GateError("clock is invalid")
        previous = db.execute(
            "SELECT last_time FROM clock_state WHERE id=1"
        ).fetchone()[0]
        if now < previous:
            raise GateError("clock moved backwards")
        db.execute("UPDATE clock_state SET last_time=? WHERE id=1", (now,))
        return now

    def plan(
        self, audience: str, mode: str, user_id: str,
        tags: list[str], ttl_seconds: int,
    ) -> tuple[str, str, float]:
        scoped_tags = canonical_tags(tags)
        if not USER_ID.fullmatch(user_id) or not 5 <= ttl_seconds <= 3600:
            raise GateError("invalid user or lifetime")
        if not self._allowed(audience, mode, user_id, scoped_tags):
            raise GateError("scope is not allowed")
        token = secrets.token_urlsafe(32)
        grant_id = secrets.token_hex(16)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            deadline = self._observe_clock(db) + ttl_seconds
            db.execute(
                "INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?)",
                (grant_id, hashlib.sha256(token.encode()).hexdigest(), audience,
                 mode, user_id, json.dumps(scoped_tags), deadline, "pending", None, None),
            )
            db.commit()
        return grant_id, token, deadline

    def _set_failed(self, grant_id: str) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE grants SET status='failed' WHERE id=? AND status='issuing'",
                (grant_id,),
            )
            db.commit()

    def redeem(
        self, token: str, audience: str, mode: str, user_id: str, tags: list[str]
    ) -> MintedKey:
        scoped_tags = canonical_tags(tags)
        if not USER_ID.fullmatch(user_id) or len(token) > 256:
            raise GateError("invalid redemption")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = self._observe_clock(db)
            row = db.execute(
                "SELECT id,audience,mode,user_id,tags_json,expires_at,status "
                "FROM grants WHERE token_hash=?", (token_hash,),
            ).fetchone()
            if row is None:
                raise GateError("grant unavailable")
            grant_id, saved_audience, saved_mode, saved_user, saved_tags, deadline, status = row
            if (status != "pending" or now >= deadline or
                    (audience, mode, user_id, scoped_tags) !=
                    (saved_audience, saved_mode, saved_user, tuple(json.loads(saved_tags))) or
                    not self._allowed(audience, mode, user_id, scoped_tags)):
                raise GateError("grant unavailable")
            db.execute("UPDATE grants SET status='issuing' WHERE id=?", (grant_id,))
            db.commit()

        remaining = int(deadline - self.clock()) - 2
        if remaining < 1:
            self._set_failed(grant_id)
            raise GateError("grant expired during issuance")
        minted = None
        try:
            minted = self.issuer.mint(user_id, scoped_tags, remaining)
            if (minted.user_id != user_id or minted.tags != scoped_tags or
                    minted.reusable is not False or minted.used is not False or
                    minted.expires_at > deadline or self.clock() >= deadline):
                raise GateError("issued key was outside the approved scope")
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute(
                    "UPDATE grants SET status='issued', key_id=?, issued_at=? "
                    "WHERE id=? AND status='issuing'",
                    (minted.key_id, self.clock(), grant_id),
                )
                if changed.rowcount != 1:
                    raise GateError("grant state changed during issuance")
                db.commit()
            return minted
        except Exception as exc:
            if minted is not None:
                try:
                    self.issuer.expire(minted.key_id)
                except Exception:
                    pass
            self._set_failed(grant_id)
            if isinstance(exc, GateError):
                raise
            raise GateError("key issuance failed") from exc

    def status(self, grant_id: str) -> dict:
        with self._connect() as db:
            row = db.execute(
                "SELECT audience,mode,user_id,tags_json,expires_at,status,key_id,issued_at "
                "FROM grants WHERE id=?", (grant_id,),
            ).fetchone()
        if row is None:
            raise GateError("grant unavailable")
        return dict(zip(
            ("audience", "mode", "user_id", "tags", "expires_at", "status",
             "key_id", "issued_at"),
            (*row[:3], json.loads(row[3]), *row[4:]),
        ))
