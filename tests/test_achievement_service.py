import os
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.achievement_service import publish_submission, validate_catalog
from app.db import (
    STATUS_APPROVED,
    AchievementCatalog,
    AchievementSubmission,
    Base,
    User,
    get_db,
)
from app.main import app


def example_catalog(set_id: str = "doom-first-launch") -> dict:
    return {
        "formatVersion": 1,
        "sets": [
            {
                "id": set_id,
                "title": "Doom Resurrection",
                "target": {
                    "bundleId": "com.idsoftware.DoomResurrection",
                    "bundleVersions": ["1.1"],
                    "executableSha256": ["a" * 64],
                },
                "achievements": [
                    {
                        "id": "first-launch",
                        "title": "First launch",
                        "description": "Start the exact tested build.",
                        "points": 5,
                        "trigger": {"type": "session-start"},
                    }
                ],
            }
        ],
    }


class AchievementValidationTests(TestCase):
    def test_accepts_exact_revision_catalog(self):
        self.assertEqual(validate_catalog(example_catalog()), example_catalog())

    def test_rejects_unknown_code_like_trigger(self):
        catalog = example_catalog()
        catalog["sets"][0]["achievements"][0]["trigger"] = {
            "type": "script",
            "code": "writeMemory()",
        }
        with self.assertRaisesRegex(ValueError, "trigger.type"):
            validate_catalog(catalog)

    def test_rejects_low_memory_address(self):
        catalog = example_catalog()
        catalog["sets"][0]["achievements"][0]["trigger"] = {
            "type": "memory",
            "all": [{"address": 12, "size": "u32", "op": "eq", "value": 1}],
        }
        with self.assertRaisesRegex(ValueError, "address"):
            validate_catalog(catalog)


class AchievementApiTests(TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"SESSION_SECRET": "x" * 48})
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
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.db.close()
        self.environment.stop()

    def test_empty_catalog_supports_etag(self):
        first = self.client.get("/v1/catalog")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), {"catalog": {"formatVersion": 1, "sets": []}})
        etag = first.headers["etag"]
        cached = self.client.get("/v1/catalog", headers={"If-None-Match": etag})
        self.assertEqual(cached.status_code, 304)

    def test_submission_is_idempotent_and_has_public_status(self):
        payload = {
            "formatVersion": 1,
            "installId": "01234567-89ab-cdef-0123-456789abcdef",
            "client": {"platform": "android", "version": "test"},
            "catalog": example_catalog(),
        }
        first = self.client.post("/v1/submissions", json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json()["duplicate"])
        second = self.client.post("/v1/submissions", json=payload)
        self.assertTrue(second.json()["duplicate"])
        status = self.client.get(first.json()["statusUrl"])
        self.assertEqual(status.json()["status"], "pending")
        self.assertEqual(self.db.query(AchievementSubmission).count(), 1)

    def test_admin_publish_merges_catalog_and_changes_etag(self):
        payload = {
            "formatVersion": 1,
            "installId": "01234567-89ab-cdef-0123-456789abcdef",
            "catalog": example_catalog(),
        }
        response = self.client.post("/v1/submissions", json=payload)
        row = self.db.get(AchievementSubmission, response.json()["id"])
        admin = User(github_id=1, github_login="joewebkid", is_admin=True)
        self.db.add(admin)
        self.db.commit()
        publish_submission(row, admin, self.db)
        self.assertEqual(row.status, STATUS_APPROVED)
        release = self.db.get(AchievementCatalog, 1)
        self.assertEqual(release.catalog["sets"][0]["id"], "doom-first-launch")
        public = self.client.get("/v1/catalog")
        self.assertEqual(public.json()["catalog"], example_catalog())

    def test_invalid_install_id_is_rejected(self):
        response = self.client.post(
            "/v1/submissions",
            json={"formatVersion": 1, "installId": "phone", "catalog": example_catalog()},
        )
        self.assertEqual(response.status_code, 400)



