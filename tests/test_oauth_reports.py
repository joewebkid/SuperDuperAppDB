import asyncio
import base64
import hashlib
import html
import io
import os
import re
from urllib.parse import parse_qs, urlsplit
from unittest import TestCase
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.auth import (
    OAUTH_NEXT_KEY,
    OAUTH_PKCE_VERIFIER_KEY,
    OAUTH_STARTED_AT_KEY,
    OAUTH_STATE_KEY,
    get_csrf_token,
    handle_callback,
    require_csrf_token,
    safe_next_path,
    start_login,
)
from app.db import Base, Report, STATUS_PENDING, User, _database_url, get_db
from app.main import app
from app.main import _read_uploaded_screenshot, _save_uploaded_screenshot
from starlette.datastructures import UploadFile


def request_with_session() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/auth/github/login",
        "query_string": b"",
        "headers": [],
        "server": ("reports.example", 443),
        "client": ("127.0.0.1", 1234),
        "session": {},
    }
    return Request(scope)


class FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


class FakeGitHubClient:
    def __init__(self, *_args, **_kwargs):
        self.token_request = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, _url, *, data, headers):
        self.token_request = {"data": data, "headers": headers}
        return FakeResponse(200, {"access_token": "test-access-token"})

    async def get(self, _url, *, headers):
        assert headers["Authorization"] == "Bearer test-access-token"
        return FakeResponse(
            200,
            {"id": 901901, "login": "community-tester", "avatar_url": None},
        )


class OAuthUnitTests(TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "GITHUB_OAUTH_CLIENT_ID": "client-id",
                "GITHUB_OAUTH_CLIENT_SECRET": "client-secret",
                "OAUTH_CALLBACK_URL": "https://reports.example/auth/github/callback",
            },
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    def test_next_path_rejects_external_and_encoded_redirects(self):
        self.assertEqual(safe_next_path("/submit?rating=4"), "/submit?rating=4")
        for value in (
            "https://evil.example/",
            "//evil.example/",
            "/%2f%2fevil.example/",
            "/\\evil.example/",
            "submit",
        ):
            self.assertIsNone(safe_next_path(value))

    def test_login_uses_pkce_and_discards_stale_next(self):
        request = request_with_session()
        request.session[OAUTH_NEXT_KEY] = "/stale"
        response = start_login(request, "/submit?rating=4")
        query = parse_qs(urlsplit(response.headers["location"]).query)
        verifier = request.session[OAUTH_PKCE_VERIFIER_KEY]
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")

        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["code_challenge"], [expected])
        self.assertEqual(query["state"], [request.session[OAUTH_STATE_KEY]])
        self.assertEqual(request.session[OAUTH_NEXT_KEY], "/submit?rating=4")
        self.assertIn(OAUTH_STARTED_AT_KEY, request.session)

    def test_callback_exchanges_verifier_and_creates_user(self):
        request = request_with_session()
        start_login(request, "/submit?rating=4")
        state = request.session[OAUTH_STATE_KEY]
        verifier = request.session[OAUTH_PKCE_VERIFIER_KEY]
        engine = create_engine("sqlite://", poolclass=StaticPool)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        fake_client = FakeGitHubClient()

        with patch("app.auth.httpx.AsyncClient", return_value=fake_client):
            response = asyncio.run(handle_callback(request, "code", state, db))

        self.assertEqual(response.headers["location"], "/submit?rating=4")
        self.assertEqual(fake_client.token_request["data"]["code_verifier"], verifier)
        user = db.query(User).one()
        self.assertEqual(user.github_login, "community-tester")
        self.assertEqual(request.session["user_id"], user.id)
        self.assertNotIn(OAUTH_STATE_KEY, request.session)
        db.close()
        engine.dispose()

    def test_invalid_state_clears_return_target(self):
        request = request_with_session()
        start_login(request, "/submit")
        engine = create_engine("sqlite://", poolclass=StaticPool)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(handle_callback(request, "code", "wrong", db))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertNotIn(OAUTH_NEXT_KEY, request.session)
        db.close()
        engine.dispose()

    def test_expired_attempt_is_rejected(self):
        request = request_with_session()
        start_login(request, "/submit")
        state = request.session[OAUTH_STATE_KEY]
        request.session[OAUTH_STARTED_AT_KEY] = 0
        engine = create_engine("sqlite://", poolclass=StaticPool)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(handle_callback(request, "code", state, db))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertNotIn(OAUTH_NEXT_KEY, request.session)
        db.close()
        engine.dispose()

    def test_csrf_is_session_bound(self):
        request = request_with_session()
        token = get_csrf_token(request)
        require_csrf_token(request, token)
        with self.assertRaises(HTTPException) as raised:
            require_csrf_token(request, "wrong")
        self.assertEqual(raised.exception.status_code, 403)

    def test_generic_postgres_url_uses_psycopg_v3(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pass@db/app"}):
            self.assertEqual(
                _database_url(),
                "postgresql+psycopg://user:pass@db/app",
            )

    def test_image_extension_cannot_hide_non_image_content(self):
        upload = UploadFile(filename="fake.png", file=io.BytesIO(b"<html>not an image"))
        filename, error = asyncio.run(_save_uploaded_screenshot(upload))
        self.assertIsNone(filename)
        self.assertIn("do not match", error)

    def test_valid_image_is_returned_for_database_storage(self):
        png = b"\x89PNG\r\n\x1a\n" + b"test-image-payload"
        upload = UploadFile(filename="screen.png", file=io.BytesIO(png))
        blob, content_type, error = asyncio.run(_read_uploaded_screenshot(upload))
        self.assertEqual(blob, png)
        self.assertEqual(content_type, "image/png")
        self.assertIsNone(error)


class OAuthReportFlowTests(TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "GITHUB_OAUTH_CLIENT_ID": "client-id",
                "GITHUB_OAUTH_CLIENT_SECRET": "client-secret",
                "OAUTH_CALLBACK_URL": "http://testserver/auth/github/callback",
            },
        )
        self.environment.start()
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()

        def override_db():
            yield self.db

        app.dependency_overrides[get_db] = override_db
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.db.close()
        self.environment.stop()

    def test_android_prefill_survives_login_and_creates_pending_report(self):
        prefill = {
            "source": "android",
            "new_app_name": "Snowboard Hero",
            "display_name": "Snowboard Hero",
            "bundle_identifier": "www.fishlabs.net.sbh",
            "version_number": "1.6",
            "touchhle_version": "test-build",
            "operating_system": "Android 16",
            "gpu": "Qualcomm Adreno",
            "rating": "3",
            "remarks": "Menu renders; buttons do not respond.",
        }
        login_page = self.client.get("/submit", params=prefill)
        self.assertEqual(login_page.status_code, 200)
        login_hrefs = [
            html.unescape(value)
            for value in re.findall(
                r'href="([^"]*?/auth/github/login[^"]*)"', login_page.text
            )
        ]
        login_href = next(value for value in login_hrefs if "?next=" in value)
        authorize = self.client.get(login_href)
        self.assertEqual(authorize.status_code, 303)
        state = parse_qs(urlsplit(authorize.headers["location"]).query)["state"][0]

        with patch("app.auth.httpx.AsyncClient", FakeGitHubClient):
            callback = self.client.get(
                "/auth/github/callback", params={"code": "code", "state": state}
            )
        self.assertEqual(callback.status_code, 303)
        self.assertIn("bundle_identifier=www.fishlabs.net.sbh", callback.headers["location"])

        form_page = self.client.get(callback.headers["location"])
        self.assertEqual(form_page.status_code, 200)
        self.assertIn('value="www.fishlabs.net.sbh"', form_page.text)
        self.assertIn('value="1.6"', form_page.text)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', form_page.text).group(1)

        rejected = self.client.post("/submit", data={"app_id": "__new__", "csrf_token": "bad"})
        self.assertEqual(rejected.status_code, 403)

        png = b"\x89PNG\r\n\x1a\n" + b"report-screenshot"
        submitted = self.client.post(
            "/submit",
            data={
                **prefill,
                "app_id": "__new__",
                "csrf_token": csrf,
                "scale_hack": "",
            },
            files={"screenshot_file": ("screen.png", png, "image/png")},
        )
        self.assertEqual(submitted.status_code, 303)
        self.assertEqual(submitted.headers["location"], "/submit/thanks")
        report = self.db.query(Report).one()
        self.assertEqual(report.status, STATUS_PENDING)
        self.assertEqual(report.bundle_identifier, "www.fishlabs.net.sbh")
        self.assertEqual(report.reporter.github_login, "community-tester")
        self.assertEqual(report.screenshot_blob, png)
        self.assertEqual(report.screenshot_content_type, "image/png")

        # Authors can see pending screenshots, while anonymous users cannot
        # see them until the report has been approved.
        owner_image = self.client.get(f"/screenshots/{report.id}")
        self.assertEqual(owner_image.status_code, 200)
        self.assertEqual(owner_image.content, png)
        self.assertEqual(owner_image.headers["content-type"], "image/png")
        anonymous = TestClient(app, follow_redirects=False)
        try:
            self.assertEqual(anonymous.get(f"/screenshots/{report.id}").status_code, 404)
            report.status = "approved"
            self.db.commit()
            public_image = anonymous.get(f"/screenshots/{report.id}")
            self.assertEqual(public_image.status_code, 200)
            self.assertEqual(public_image.content, png)
        finally:
            anonymous.close()
