from copy import deepcopy
from unittest import TestCase

from pydantic import ValidationError

from app.patch_submissions import PatchSubmissionRequest


def valid_payload() -> dict:
    return {
        "manifest": {
            "formatVersion": 1,
            "id": "sample-present-flip",
            "name": "Sample present flip",
            "kind": "compatibility",
            "status": "experimental",
            "defaultEnabled": False,
            "priority": 100,
            "target": {
                "bundleId": "com.example.game",
                "bundleVersions": ["1.0"],
                "executableSha256": ["a" * 64],
                "allowLegacyWeakMatch": False,
            },
            "actions": {"presentation": {"presentFlipX": True}},
        },
        "evidence": {
            "gameTitle": "Sample",
            "device": "Test device",
            "android": "15 (SDK 35)",
            "appVersion": "test",
            "notes": "test",
        },
    }


def valid_input_payload() -> dict:
    payload = valid_payload()
    payload["manifest"].update(
        {
            "id": "sample-controller",
            "name": "Sample controller layout",
            "kind": "input",
            "actions": {
                "input": {
                    "buttons": [
                        {"button": "A", "x": 420, "y": 280},
                        {"button": "RightShoulder", "x": 455, "y": 220},
                    ],
                    "leftDeadzone": 0.1,
                    "rightDeadzone": 0.15,
                    "accelerometerMode": "gamepad",
                    "tiltStick": "left",
                    "cursorStick": "right",
                }
            },
        }
    )
    return payload


class PatchSubmissionValidationTests(TestCase):
    def test_half_turn_is_a_typed_compatibility_action(self):
        payload = valid_payload()
        payload["manifest"]["actions"] = {"presentation": {"presentRotate180": True}}
        parsed = PatchSubmissionRequest.model_validate(payload)
        self.assertTrue(parsed.manifest.actions.presentation.presentRotate180)
        payload["manifest"]["kind"] = "presentation-layout"
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_cursor_patch_can_be_submitted_with_orientation_layouts(self):
        payload = valid_input_payload()
        payload["manifest"]["actions"]["input"] = {
            "cursorMode": "relative", "cursorClickButton": "A",
            "landscapeLayout": {"buttons": [{"button": "B", "x": 10, "y": 20}]},
        }
        parsed = PatchSubmissionRequest.model_validate(payload)
        self.assertEqual(parsed.manifest.actions.input.cursorMode, "relative")
        for changes in ({"cursorClickButton": "Back"}, {"cursorClickButton": "B"},
                        {"cursorMode": "script"}):
            invalid = deepcopy(payload)
            invalid["manifest"]["actions"]["input"].update(changes)
            with self.assertRaises(ValidationError):
                PatchSubmissionRequest.model_validate(invalid)

    def test_accepts_exact_typed_manifest(self) -> None:
        parsed = PatchSubmissionRequest.model_validate(valid_payload())
        self.assertEqual(parsed.manifest.target.executableSha256, ["a" * 64])

    def test_rejects_weak_target(self) -> None:
        payload = deepcopy(valid_payload())
        payload["manifest"]["target"]["allowLegacyWeakMatch"] = True
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_rejects_arbitrary_action(self) -> None:
        payload = deepcopy(valid_payload())
        payload["manifest"]["actions"]["script"] = "arbitrary code"
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_rejects_default_enabled_community_patch(self) -> None:
        payload = deepcopy(valid_payload())
        payload["manifest"]["defaultEnabled"] = True
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_accepts_full_typed_input_profile(self) -> None:
        parsed = PatchSubmissionRequest.model_validate(valid_input_payload())
        self.assertEqual(parsed.manifest.kind, "input")
        self.assertEqual(parsed.manifest.actions.input.tiltStick, "left")

    def test_rejects_stick_role_conflict(self) -> None:
        payload = valid_input_payload()
        payload["manifest"]["actions"]["input"]["leftStickToTouch"] = {
            "x": 20,
            "y": 180,
            "width": 100,
            "height": 110,
        }
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_rejects_mismatched_kind_and_actions(self) -> None:
        payload = valid_input_payload()
        payload["manifest"]["kind"] = "compatibility"
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)

    def test_accepts_full_typed_compatibility_profile(self) -> None:
        payload = valid_payload()
        payload["manifest"]["actions"] = {
            "presentation": {"disableTouchRotation": True},
            "eagl": {"forceLandscapeRenderbuffer": True},
            "gles": {"forceLandscapeViewport": True},
        }
        parsed = PatchSubmissionRequest.model_validate(payload)
        self.assertTrue(parsed.manifest.actions.gles.forceLandscapeViewport)

    def test_accepts_presentation_layout(self) -> None:
        payload = valid_payload()
        payload["manifest"].update(
            {
                "id": "sample-widescreen",
                "kind": "presentation-layout",
                "actions": {"presentation": {"outputFit": "stretch"}},
            }
        )
        parsed = PatchSubmissionRequest.model_validate(payload)
        self.assertEqual(parsed.manifest.actions.presentation.outputFit, "stretch")

    def test_rejects_relation_overlap(self) -> None:
        payload = valid_payload()
        payload["manifest"]["dependsOn"] = ["sample-base"]
        payload["manifest"]["conflictsWith"] = ["sample-base"]
        with self.assertRaises(ValidationError):
            PatchSubmissionRequest.model_validate(payload)
