"""Strict anonymous gateway from the Android app to the patch review queue."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import timedelta
from typing import Literal

import httpx
from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from .db import PatchSubmission, utcnow


ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,95}$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DEFAULT_REPOSITORY = "joewebkid/SuperDuperPatches"
GATEWAY_LABEL = "gateway-submission"
MAX_PER_CLIENT_HOUR = 3


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class PatchTarget(StrictModel):
    bundleId: str = Field(min_length=1, max_length=200)
    bundleVersions: list[str] = Field(min_length=1, max_length=8)
    executableSha256: list[str] = Field(min_length=1, max_length=8)
    allowLegacyWeakMatch: Literal[False] = False

    @field_validator("bundleId")
    @classmethod
    def validate_bundle_id(cls, value: str) -> str:
        if not BUNDLE_RE.fullmatch(value) or ".." in value:
            raise ValueError("invalid bundle ID")
        return value

    @field_validator("bundleVersions")
    @classmethod
    def validate_versions(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("invalid bundle version")
        if len(values) != len(set(values)):
            raise ValueError("duplicate bundle version")
        return values

    @field_validator("executableSha256")
    @classmethod
    def validate_hashes(cls, values: list[str]) -> list[str]:
        if any(not SHA256_RE.fullmatch(value) for value in values):
            raise ValueError("invalid executable SHA-256")
        lowered = [value.lower() for value in values]
        if len(lowered) != len(set(lowered)):
            raise ValueError("duplicate executable SHA-256")
        return lowered


class PresentationActions(StrictModel):
    presentFlipX: bool | None = None
    presentRotate180: bool | None = None
    correctLandscapeAutorotationLayout: bool | None = None
    disablePresentRotation: bool | None = None
    disableTouchRotation: bool | None = None
    outputFit: Literal["aspect-fit", "stretch"] | None = None
    startupDeviceOrientation: Literal[
        "portrait",
        "portrait-upside-down",
        "landscape-left",
        "landscape-right",
    ] | None = None


class EaglActions(StrictModel):
    recoverSharedRenderbufferStorage: bool | None = None
    forceLandscapeRenderbuffer: bool | None = None


class GlesActions(StrictModel):
    disableInactiveVertexAttributes: bool | None = None
    forceLandscapeViewport: bool | None = None


InputButton = Literal[
    "DPadLeft",
    "DPadUp",
    "DPadRight",
    "DPadDown",
    "Start",
    "Back",
    "A",
    "B",
    "X",
    "Y",
    "LeftStick",
    "RightStick",
    "LeftShoulder",
    "RightShoulder",
]
AccelerometerMode = Literal["auto", "device", "gamepad", "off"]
StickSelection = Literal["auto", "none", "left", "right"]


class ButtonTouch(StrictModel):
    button: InputButton
    x: float = Field(ge=0, le=8192)
    y: float = Field(ge=0, le=8192)


class TouchArea(StrictModel):
    x: float = Field(ge=0, le=8192)
    y: float = Field(ge=0, le=8192)
    width: float = Field(gt=0, le=8192)
    height: float = Field(gt=0, le=8192)


class CursorStabilization(StrictModel):
    smoothingStrength: float = Field(ge=0)
    stickyRadius: float = Field(ge=0)


class OrientationInputLayout(StrictModel):
    buttons: list[ButtonTouch] = Field(default_factory=list, max_length=14)
    dpadToTouch: TouchArea | None = None
    leftStickToTouch: TouchArea | None = None
    rightStickToTouch: TouchArea | None = None

    @model_validator(mode="after")
    def validate_layout(self) -> "OrientationInputLayout":
        buttons = [binding.button for binding in self.buttons]
        if len(buttons) != len(set(buttons)):
            raise ValueError("duplicate orientation button")
        if not any(value is not None and value != [] for value in self.model_dump().values()):
            raise ValueError("orientation layout cannot be empty")
        return self


class InputActions(StrictModel):
    buttons: list[ButtonTouch] = Field(default_factory=list, max_length=14)
    dpadToTouch: TouchArea | None = None
    stickToTouch: TouchArea | None = None
    leftStickToTouch: TouchArea | None = None
    rightStickToTouch: TouchArea | None = None
    leftDeadzone: float | None = Field(default=None, ge=0, lt=1)
    rightDeadzone: float | None = Field(default=None, ge=0, lt=1)
    accelerometerMode: AccelerometerMode | None = None
    tiltStick: StickSelection | None = None
    cursorStick: StickSelection | None = None
    cursorMode: Literal["absolute", "relative"] | None = None
    cursorClickButton: Literal["A", "B", "X", "Y", "LeftStick", "RightStick", "LeftShoulder", "RightShoulder"] | None = None
    portraitLayout: OrientationInputLayout | None = None
    landscapeLayout: OrientationInputLayout | None = None
    xTiltRange: float | None = Field(default=None, ge=0, le=360)
    yTiltRange: float | None = Field(default=None, ge=0, le=360)
    xTiltOffset: float | None = Field(default=None, ge=-360, le=360)
    yTiltOffset: float | None = Field(default=None, ge=-360, le=360)
    stabilizeVirtualCursor: CursorStabilization | None = None

    @model_validator(mode="after")
    def validate_roles(self) -> "InputActions":
        if self.stickToTouch is not None and self.leftStickToTouch is not None:
            raise ValueError("stickToTouch and leftStickToTouch cannot be combined")
        button_names = [binding.button for binding in self.buttons]
        if len(button_names) != len(set(button_names)):
            raise ValueError("an input button cannot be mapped more than once")
        layouts = [layout for layout in (self.portraitLayout, self.landscapeLayout) if layout is not None]
        all_buttons = button_names + [binding.button for layout in layouts for binding in layout.buttons]
        if self.cursorClickButton is not None and self.cursorClickButton in all_buttons:
            raise ValueError("cursor click button also has a fixed touch binding")
        if not any(
            value is not None and value != []
            for value in self.model_dump(exclude_none=True).values()
        ):
            raise ValueError("input actions cannot be empty")

        left_touch = self.stickToTouch is not None or self.leftStickToTouch is not None or any(
            layout.leftStickToTouch is not None for layout in layouts)
        right_touch = self.rightStickToTouch is not None or any(
            layout.rightStickToTouch is not None for layout in layouts)
        mode = self.accelerometerMode or "auto"
        tilt_selection = self.tiltStick or "auto"
        cursor_selection = self.cursorStick or "auto"
        tilt_active = mode in {"auto", "gamepad"}
        explicit_tilt = (
            tilt_selection
            if tilt_active and tilt_selection in {"left", "right"}
            else None
        )
        explicit_cursor = (
            cursor_selection if cursor_selection in {"left", "right"} else None
        )
        if (explicit_tilt == "left" and left_touch) or (
            explicit_tilt == "right" and right_touch
        ):
            raise ValueError("one stick cannot control both tilt and touch")
        if (explicit_cursor == "left" and left_touch) or (
            explicit_cursor == "right" and right_touch
        ):
            raise ValueError("one stick cannot control both cursor and touch")
        if explicit_tilt is not None and explicit_tilt == explicit_cursor:
            raise ValueError("one stick cannot control both tilt and cursor")
        resolved_tilt = explicit_tilt
        if (
            resolved_tilt is None
            and tilt_active
            and tilt_selection == "auto"
            and not left_touch
            and explicit_cursor != "left"
        ):
            resolved_tilt = "left"
        if mode == "gamepad" and resolved_tilt is None:
            raise ValueError("gamepad accelerometer mode needs an unassigned tilt stick")
        return self


class PatchActions(StrictModel):
    presentation: PresentationActions | None = None
    eagl: EaglActions | None = None
    gles: GlesActions | None = None
    input: InputActions | None = None


class PatchManifest(StrictModel):
    schema_: str | None = Field(default=None, alias="$schema", max_length=200)
    formatVersion: Literal[1]
    id: str = Field(min_length=1, max_length=96)
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["compatibility", "presentation-layout", "input"]
    status: Literal["experimental"]
    defaultEnabled: Literal[False]
    priority: int = Field(default=100, ge=0, le=1000)
    dependsOn: list[str] = Field(default_factory=list, max_length=16)
    conflictsWith: list[str] = Field(default_factory=list, max_length=16)
    target: PatchTarget
    actions: PatchActions

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not ID_RE.fullmatch(value):
            raise ValueError("invalid patch ID")
        return value

    @field_validator("dependsOn", "conflictsWith")
    @classmethod
    def validate_relations(cls, values: list[str]) -> list[str]:
        if any(not ID_RE.fullmatch(value) for value in values):
            raise ValueError("invalid related patch ID")
        if len(values) != len(set(values)):
            raise ValueError("duplicate related patch ID")
        return values

    @model_validator(mode="after")
    def validate_kind_actions(self) -> "PatchManifest":
        if self.id in self.dependsOn or self.id in self.conflictsWith:
            raise ValueError("a patch cannot reference itself")
        if set(self.dependsOn) & set(self.conflictsWith):
            raise ValueError("a patch cannot both depend on and conflict with one ID")
        action_data = {
            key: value
            for key, value in self.actions.model_dump(exclude_none=True).items()
            if value
        }
        if self.kind == "compatibility":
            if self.actions.input is not None or not action_data:
                raise ValueError("compatibility submissions need presentation/EAGL/GLES actions")
            if self.actions.presentation is not None and self.actions.presentation.outputFit is not None:
                raise ValueError("outputFit belongs to presentation-layout")
        elif self.kind == "presentation-layout":
            presentation = self.actions.presentation
            if (
                set(action_data) != {"presentation"}
                or presentation is None
                or set(presentation.model_dump(exclude_none=True)) != {"outputFit"}
            ):
                raise ValueError("presentation-layout requires only presentation.outputFit")
        elif self.actions.input is None or set(action_data) != {"input"}:
            raise ValueError("input submissions require only typed input actions")
        return self


class PatchEvidence(StrictModel):
    gameTitle: str = Field(min_length=1, max_length=200)
    device: str = Field(min_length=1, max_length=160)
    android: str = Field(min_length=1, max_length=80)
    appVersion: str = Field(min_length=1, max_length=80)
    notes: str = Field(default="Submitted from the in-app patch editor.", max_length=2000)


class PatchSubmissionRequest(StrictModel):
    manifest: PatchManifest
    evidence: PatchEvidence


def _configuration() -> tuple[str, str]:
    token = os.environ.get("PATCH_SUBMISSION_GITHUB_TOKEN", "").strip()
    repository = os.environ.get("PATCH_SUBMISSION_REPOSITORY", DEFAULT_REPOSITORY).strip()
    if not token:
        raise HTTPException(503, "Patch submission gateway is not configured.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise HTTPException(503, "Patch submission repository is invalid.")
    return token, repository


def _canonical_manifest(payload: PatchSubmissionRequest) -> tuple[dict, str]:
    manifest = payload.manifest.model_dump(by_alias=True, exclude_none=True)
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return manifest, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _client_hash(request: Request, secret: str) -> str:
    # Hosting proxies must replace, not append to, these headers. The database
    # stores only an HMAC so public IP addresses never become moderation data.
    address = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("fly-client-ip")
        or (request.client.host if request.client else "unknown")
    )
    salt = os.environ.get("PATCH_SUBMISSION_RATE_SALT", "").strip() or secret
    return hmac.new(salt.encode(), address.encode(), hashlib.sha256).hexdigest()


def _issue_body(payload: PatchSubmissionRequest, manifest: dict) -> str:
    evidence = payload.evidence
    return "\n".join(
        [
            "Submitted automatically from the Super Duper Android patch editor.",
            "",
            "## Automatically collected evidence",
            f"- Game: {evidence.gameTitle}",
            f"- Device: {evidence.device}",
            f"- Android: {evidence.android}",
            f"- Super Duper: {evidence.appVersion}",
            f"- Notes: {evidence.notes}",
            "",
            "A maintainer must still reproduce the result and test rollback before merge.",
            "",
            "<!-- sdpatch-json:start -->",
            json.dumps(manifest, ensure_ascii=False, indent=2),
            "<!-- sdpatch-json:end -->",
        ]
    )


async def submit_patch(
    request: Request,
    payload: PatchSubmissionRequest,
    db: Session,
) -> dict:
    """Validate, rate-limit and create one idempotent GitHub review issue."""

    token, repository = _configuration()
    manifest, fingerprint = _canonical_manifest(payload)
    existing = (
        db.query(PatchSubmission)
        .filter(PatchSubmission.fingerprint == fingerprint)
        .first()
    )
    if existing and existing.issue_url:
        return {"ok": True, "duplicate": True, "issueUrl": existing.issue_url}

    client_hash = _client_hash(request, token)
    cutoff = utcnow() - timedelta(hours=1)
    recent = (
        db.query(PatchSubmission)
        .filter(PatchSubmission.client_hash == client_hash)
        .filter(PatchSubmission.submitted_at >= cutoff)
        .count()
    )
    limit = max(1, min(20, int(os.environ.get("PATCH_SUBMISSION_MAX_PER_HOUR", MAX_PER_CLIENT_HOUR))))
    if recent >= limit:
        raise HTTPException(429, "Patch submission limit reached. Try again later.")

    body = _issue_body(payload, manifest)
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Super-Duper-Patch-Gateway/1",
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            f"https://api.github.com/repos/{repository}/issues",
            headers=headers,
            json={
                "title": f"[Patch] {payload.manifest.name}",
                "body": body,
                "labels": [GATEWAY_LABEL],
            },
        )
    if response.status_code not in (200, 201):
        raise HTTPException(502, f"GitHub rejected the review submission ({response.status_code}).")
    result = response.json()
    issue_url = str(result.get("html_url") or "")
    if not issue_url.startswith("https://github.com/"):
        raise HTTPException(502, "GitHub returned an invalid issue URL.")

    row = existing or PatchSubmission(
        fingerprint=fingerprint,
        client_hash=client_hash,
        patch_id=payload.manifest.id,
        bundle_identifier=payload.manifest.target.bundleId,
    )
    row.issue_url = issue_url
    if existing is None:
        db.add(row)
    db.commit()
    return {"ok": True, "duplicate": False, "issueUrl": issue_url}
