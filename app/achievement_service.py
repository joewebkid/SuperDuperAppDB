"""Moderated achievement-catalog API used by the Android client.

Remote catalogs are data only: they may describe exact-revision GameKit or
read-only memory triggers, but cannot carry code or write guest memory.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import timedelta
from typing import Any

from fastapi import HTTPException, Request, Response
from sqlalchemy.orm import Session

from .db import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    AchievementCatalog,
    AchievementSubmission,
    User,
    utcnow,
)

FORMAT_VERSION = 1
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_SETS = 64
MAX_ACHIEVEMENTS = 512
MAX_CONDITIONS = 32
MAX_DAILY_SUBMISSIONS = 10
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
INSTALL_ID_RE = re.compile(r"^[0-9a-f-]{20,64}$", re.IGNORECASE)
ADDRESS_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
SIZES = {"u8", "u16", "u32", "i8", "i16", "i32"}
OPERATORS = {"eq", "ne", "lt", "le", "gt", "ge", "changed", "increased", "decreased"}
_submission_lock = threading.Lock()


def _fail(message: str) -> None:
    raise ValueError(message)


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{name} must be an object")
    return value


def _keys(
    value: dict[str, Any], allowed: set[str], name: str, required: set[str] | None = None
) -> None:
    required = allowed if required is None else required
    missing = required.difference(value)
    if missing:
        _fail(f"{name}.{sorted(missing)[0]} is required")
    unexpected = set(value).difference(allowed)
    if unexpected:
        _fail(f"{name}.{sorted(unexpected)[0]} is not supported")


def _array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{name} must be an array")
    return value


def _text(value: Any, name: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _fail(f"{name} must be a non-empty string of at most {maximum} characters")
    return value


def _string_array(value: Any, name: str) -> list[str]:
    values = [_text(item, f"{name}[{index}]", 200) for index, item in enumerate(_array(value, name))]
    if not values:
        _fail(f"{name} must not be empty")
    if len(values) != len(set(values)):
        _fail(f"{name} contains duplicates")
    return values


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _fail(f"{name} is invalid")
    return value


def _conditions(value: Any, name: str, *, non_empty: bool) -> None:
    values = _array([] if value is None else value, name)
    if (non_empty and not values) or len(values) > MAX_CONDITIONS:
        _fail(f"{name} has an invalid number of conditions")
    for index, raw in enumerate(values):
        prefix = f"{name}[{index}]"
        condition = _object(raw, prefix)
        _keys(condition, {"address", "size", "op", "value", "mask"}, prefix, {"address", "size", "op"})
        address = condition["address"]
        if isinstance(address, bool) or not (
            isinstance(address, int) and 4096 <= address <= 0xFFFFFFFF
            or isinstance(address, str) and ADDRESS_RE.fullmatch(address)
            and 4096 <= int(address, 0) <= 0xFFFFFFFF
        ):
            _fail(f"{prefix}.address is invalid")
        if _text(condition["size"], f"{prefix}.size", 3) not in SIZES:
            _fail(f"{prefix}.size is invalid")
        if _text(condition["op"], f"{prefix}.op", 16) not in OPERATORS:
            _fail(f"{prefix}.op is invalid")
        if "value" in condition:
            _integer(condition["value"], f"{prefix}.value", -(2**63), 2**63 - 1)
        if condition.get("mask") is not None:
            _integer(condition["mask"], f"{prefix}.mask", 0, 0xFFFFFFFF)


def validate_catalog(value: Any) -> dict[str, Any]:
    """Return a validated JSON-compatible catalog without adding defaults."""

    catalog = _object(value, "catalog")
    _keys(catalog, {"formatVersion", "sets"}, "catalog")
    if catalog["formatVersion"] != FORMAT_VERSION:
        _fail("unsupported formatVersion")
    sets = _array(catalog["sets"], "sets")
    if len(sets) > MAX_SETS:
        _fail("too many sets")
    total = 0
    set_ids: set[str] = set()
    for set_index, raw_set in enumerate(sets):
        prefix = f"sets[{set_index}]"
        achievement_set = _object(raw_set, prefix)
        _keys(achievement_set, {"id", "title", "target", "achievements"}, prefix)
        set_id = _text(achievement_set["id"], f"{prefix}.id", 200)
        if set_id in set_ids:
            _fail(f"{prefix}.id is duplicated")
        set_ids.add(set_id)
        _text(achievement_set["title"], f"{prefix}.title", 200)
        target = _object(achievement_set["target"], f"{prefix}.target")
        _keys(target, {"bundleId", "bundleVersions", "executableSha256"}, f"{prefix}.target")
        _text(target["bundleId"], f"{prefix}.target.bundleId", 200)
        _string_array(target["bundleVersions"], f"{prefix}.target.bundleVersions")
        hashes = _string_array(target["executableSha256"], f"{prefix}.target.executableSha256")
        if any(not SHA256_RE.fullmatch(item) for item in hashes):
            _fail("invalid executable SHA-256")
        achievements = _array(achievement_set["achievements"], f"{prefix}.achievements")
        total += len(achievements)
        if total > MAX_ACHIEVEMENTS:
            _fail("too many achievements")
        achievement_ids: set[str] = set()
        for achievement_index, raw_achievement in enumerate(achievements):
            item_prefix = f"{prefix}.achievements[{achievement_index}]"
            achievement = _object(raw_achievement, item_prefix)
            _keys(achievement, {"id", "title", "description", "points", "trigger"}, item_prefix)
            achievement_id = _text(achievement["id"], f"{item_prefix}.id", 200)
            if achievement_id in achievement_ids:
                _fail(f"{item_prefix}.id is duplicated")
            achievement_ids.add(achievement_id)
            _text(achievement["title"], f"{item_prefix}.title", 120)
            description = achievement["description"]
            if not isinstance(description, str) or len(description) > 500:
                _fail(f"{item_prefix}.description is invalid")
            _integer(achievement["points"], f"{item_prefix}.points", 0, 1000)
            trigger = _object(achievement["trigger"], f"{item_prefix}.trigger")
            trigger_type = _text(trigger.get("type"), f"{item_prefix}.trigger.type", 20)
            if trigger_type == "game-kit":
                _keys(trigger, {"type", "identifier"}, f"{item_prefix}.trigger")
                _text(trigger["identifier"], f"{item_prefix}.trigger.identifier", 200)
            elif trigger_type == "memory":
                _keys(
                    trigger,
                    {"type", "all", "pauseIf", "resetIf", "requiredHits"},
                    f"{item_prefix}.trigger",
                    {"type", "all"},
                )
                _conditions(trigger["all"], f"{item_prefix}.trigger.all", non_empty=True)
                _conditions(trigger.get("pauseIf"), f"{item_prefix}.trigger.pauseIf", non_empty=False)
                _conditions(trigger.get("resetIf"), f"{item_prefix}.trigger.resetIf", non_empty=False)
                _integer(trigger.get("requiredHits", 1), f"{item_prefix}.trigger.requiredHits", 1, 1_000_000)
            elif trigger_type == "session-start":
                _keys(trigger, {"type"}, f"{item_prefix}.trigger")
            else:
                _fail(f"{item_prefix}.trigger.type is invalid")
    return catalog


def canonical_catalog(catalog: dict[str, Any]) -> bytes:
    return json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def catalog_etag(catalog: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_catalog(catalog)).hexdigest()


def current_catalog(db: Session) -> AchievementCatalog:
    row = db.get(AchievementCatalog, 1)
    if row is None:
        empty = {"formatVersion": FORMAT_VERSION, "sets": []}
        row = AchievementCatalog(id=1, catalog=empty, etag=catalog_etag(empty))
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def get_catalog(request: Request, response: Response, db: Session) -> dict[str, Any] | Response:
    row = current_catalog(db)
    quoted_etag = f'"{row.etag}"'
    if request.headers.get("if-none-match") == quoted_etag:
        return Response(status_code=304, headers={"ETag": quoted_etag})
    response.headers["ETag"] = quoted_etag
    response.headers["Cache-Control"] = "public, max-age=300, stale-while-revalidate=3600"
    return {"catalog": validate_catalog(row.catalog)}


def submit_catalog(request: Request, payload: Any, db: Session) -> dict[str, Any]:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        raise HTTPException(413, "request too large")
    try:
        body = _object(payload, "request")
        _keys(body, {"formatVersion", "installId", "client", "catalog"}, "request", {"formatVersion", "installId", "catalog"})
        if body["formatVersion"] != FORMAT_VERSION:
            _fail("unsupported formatVersion")
        install_id = _text(body["installId"], "installId", 64)
        if not INSTALL_ID_RE.fullmatch(install_id):
            _fail("invalid installId")
        client = body.get("client")
        if client is not None:
            client = _object(client, "client")
            if len(canonical_catalog(client)) > 4096:
                _fail("client metadata is too large")
        catalog = validate_catalog(body["catalog"])
        encoded = canonical_catalog(catalog)
        if len(encoded) > MAX_BODY_BYTES:
            _fail("catalog too large")
    except ValueError as error:
        raise HTTPException(400, str(error)) from error

    digest = hashlib.sha256(encoded).hexdigest()
    anonymous_key = hashlib.sha256(install_id.encode("utf-8")).hexdigest()
    status_url = str(request.url_for("achievement_submission_status", submission_id=digest))
    with _submission_lock:
        existing = db.get(AchievementSubmission, digest)
        if existing is not None:
            return {"ok": True, "id": digest, "duplicate": True, "statusUrl": status_url}
        cutoff = utcnow() - timedelta(days=1)
        count = db.query(AchievementSubmission).filter(
            AchievementSubmission.anonymous_key == anonymous_key,
            AchievementSubmission.created_at >= cutoff,
        ).count()
        if count >= MAX_DAILY_SUBMISSIONS:
            raise HTTPException(429, "daily anonymous submission limit reached")
        db.add(AchievementSubmission(
            id=digest,
            anonymous_key=anonymous_key,
            catalog=catalog,
            client=client,
            status=STATUS_PENDING,
        ))
        db.commit()
    return {"ok": True, "id": digest, "duplicate": False, "statusUrl": status_url}


def submission_status(submission_id: str, db: Session) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(submission_id):
        raise HTTPException(404, "submission not found")
    row = db.get(AchievementSubmission, submission_id.lower())
    if row is None:
        raise HTTPException(404, "submission not found")
    return {"ok": True, "id": row.id, "status": row.status}


def publish_submission(row: AchievementSubmission, admin: User, db: Session) -> None:
    incoming = validate_catalog(row.catalog)
    release = current_catalog(db)
    base = validate_catalog(release.catalog)
    by_id = {item["id"]: item for item in base["sets"]}
    for item in incoming["sets"]:
        by_id[item["id"]] = item
    merged = validate_catalog({"formatVersion": FORMAT_VERSION, "sets": list(by_id.values())})
    release.catalog = merged
    release.etag = catalog_etag(merged)
    release.updated_at = utcnow()
    row.status = STATUS_APPROVED
    row.reviewed_by_id = admin.id
    row.reviewed_at = utcnow()
    row.rejection_reason = None
    db.commit()


def reject_submission(row: AchievementSubmission, reason: str, admin: User, db: Session) -> None:
    row.status = STATUS_REJECTED
    row.reviewed_by_id = admin.id
    row.reviewed_at = utcnow()
    row.rejection_reason = reason[:500] or None
    db.commit()


