"""
Unit tests for malimite_ci.py.

Network calls are mocked at urllib.request.urlopen, so these run without a live
malimite-web server. The end-to-end smoke test against a real server (verified
manually during development against the dvba_v1.1.0.apk sample — 51 findings,
7 HIGH, --fail-on HIGH correctly exits 1) is not automated here since it needs
Ghidra/JADX and a running service; see tools/malimite-ci/README.md.
"""
import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import malimite_ci  # noqa: E402


def _vuln(severity, status="open", effective_severity=None):
    return {
        "id": 1, "rule_id": "MASTG-TEST-0000", "title": "t",
        "severity": severity, "status": status,
        "effective_severity": effective_severity,
    }


class SeverityGateTests(unittest.TestCase):
    """Pure-function tests for the severity-gating logic — no network involved."""

    def test_active_findings_excludes_false_positive_and_fixed(self):
        vulns = [_vuln("HIGH", "open"), _vuln("HIGH", "false_positive"), _vuln("HIGH", "fixed")]
        active = malimite_ci.active_findings(vulns)
        self.assertEqual(len(active), 1)

    def test_active_findings_keeps_accepted_risk(self):
        # accepted_risk is reviewed but not suppressed — matches VulnerabilityRecord.isSuppressed()
        vulns = [_vuln("HIGH", "accepted_risk")]
        self.assertEqual(len(malimite_ci.active_findings(vulns)), 1)

    def test_fail_on_high_trips_on_high(self):
        self.assertTrue(malimite_ci.should_fail([_vuln("HIGH")], "HIGH"))

    def test_fail_on_high_does_not_trip_on_medium(self):
        self.assertFalse(malimite_ci.should_fail([_vuln("MEDIUM")], "HIGH"))

    def test_fail_on_medium_trips_on_medium(self):
        self.assertTrue(malimite_ci.should_fail([_vuln("MEDIUM")], "MEDIUM"))

    def test_fail_on_low_trips_on_any_finding(self):
        self.assertTrue(malimite_ci.should_fail([_vuln("INFO")], "LOW"))
        self.assertTrue(malimite_ci.should_fail([_vuln("LOW")], "LOW"))

    def test_fail_on_none_never_trips(self):
        self.assertFalse(malimite_ci.should_fail([_vuln("CRITICAL")], "NONE"))

    def test_critical_counts_as_high(self):
        self.assertTrue(malimite_ci.should_fail([_vuln("CRITICAL")], "HIGH"))

    def test_no_findings_never_trips(self):
        self.assertFalse(malimite_ci.should_fail([], "LOW"))

    def test_effective_severity_overrides_original(self):
        # a reviewer downgraded HIGH to LOW via triage — the gate must honor that.
        downgraded = _vuln("HIGH", "open", effective_severity="LOW")
        self.assertFalse(malimite_ci.should_fail([downgraded], "HIGH"))

    def test_effective_severity_can_escalate(self):
        escalated = _vuln("MEDIUM", "open", effective_severity="HIGH")
        self.assertTrue(malimite_ci.should_fail([escalated], "HIGH"))

    def test_severity_counts_aggregates_correctly(self):
        vulns = [_vuln("HIGH"), _vuln("HIGH"), _vuln("MEDIUM")]
        counts = malimite_ci.severity_counts(vulns)
        self.assertEqual(counts, {"HIGH": 2, "MEDIUM": 1})


def _http_response(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


class CiMetadataDetectionTests(unittest.TestCase):
    """detect_ci_metadata() reads well-known CI env vars; always run with a clean environment
    so one CI system's vars (e.g. this very GitHub Actions job) don't leak into assertions
    about a different system."""

    def _run_detect(self, env: dict) -> dict:
        with patch.dict(os.environ, env, clear=True):
            return malimite_ci.detect_ci_metadata()

    def test_detects_nothing_outside_any_known_ci(self):
        self.assertEqual(self._run_detect({}), {})

    def test_detects_bitbucket_pipelines(self):
        detected = self._run_detect({
            "BITBUCKET_BUILD_NUMBER": "42",
            "BITBUCKET_REPO_FULL_NAME": "myorg/myapp",
            "BITBUCKET_COMMIT": "abc1234",
        })
        self.assertEqual(detected["ci_pipeline_url"],
                         "https://bitbucket.org/myorg/myapp/pipelines/results/42")
        self.assertEqual(detected["ci_commit_sha"], "abc1234")
        self.assertEqual(detected["ci_triggered_by"], "bitbucket-pipelines")

    def test_detects_jenkins(self):
        detected = self._run_detect({
            "JENKINS_URL": "https://jenkins.internal/",
            "BUILD_URL": "https://jenkins.internal/job/myapp/42/",
            "GIT_COMMIT": "deadbeef",
        })
        self.assertEqual(detected["ci_pipeline_url"], "https://jenkins.internal/job/myapp/42/")
        self.assertEqual(detected["ci_commit_sha"], "deadbeef")
        self.assertEqual(detected["ci_triggered_by"], "jenkins")

    def test_detects_github_actions(self):
        detected = self._run_detect({
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "myorg/myapp",
            "GITHUB_RUN_ID": "99",
            "GITHUB_SHA": "cafef00d",
        })
        self.assertEqual(detected["ci_pipeline_url"], "https://github.com/myorg/myapp/actions/runs/99")
        self.assertEqual(detected["ci_commit_sha"], "cafef00d")
        self.assertEqual(detected["ci_triggered_by"], "github-actions")

    def test_bitbucket_takes_priority_when_somehow_both_present(self):
        detected = self._run_detect({
            "BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_REPO_FULL_NAME": "a/b",
            "JENKINS_URL": "https://jenkins.internal/",
        })
        self.assertEqual(detected["ci_triggered_by"], "bitbucket-pipelines")

    def test_explicit_flags_override_autodetection_in_main(self):
        """--ci-* flags win over env-var auto-detection — covers the operator-override path."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"x")
            apk_path = f.name
        try:
            mock = MagicMock(side_effect=[
                _http_response({"scan_id": "s1"}),
                _http_response({"state": "done"}),
                _http_response([]),
            ])
            env = {"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_REPO_FULL_NAME": "a/b"}
            with patch.dict(os.environ, env, clear=True), patch("urllib.request.urlopen", mock):
                malimite_ci.main([
                    "--url", "http://x", "--api-key", "k", "--file", apk_path,
                    "--fail-on", "HIGH", "--ci-triggered-by", "manual-override",
                ])
            # inspect the multipart body of the upload (first) call for the overridden value
            upload_call = mock.call_args_list[0]
            request_obj = upload_call.args[0]
            body = request_obj.data
            self.assertIn(b"manual-override", body)
            self.assertNotIn(b"bitbucket-pipelines", body)
        finally:
            Path(apk_path).unlink(missing_ok=True)

    def test_no_ci_autodetect_flag_suppresses_detection(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"x")
            apk_path = f.name
        try:
            mock = MagicMock(side_effect=[
                _http_response({"scan_id": "s1"}),
                _http_response({"state": "done"}),
                _http_response([]),
            ])
            env = {"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_REPO_FULL_NAME": "a/b"}
            with patch.dict(os.environ, env, clear=True), patch("urllib.request.urlopen", mock):
                malimite_ci.main([
                    "--url", "http://x", "--api-key", "k", "--file", apk_path,
                    "--fail-on", "HIGH", "--no-ci-autodetect",
                ])
            upload_call = mock.call_args_list[0]
            body = upload_call.args[0].data
            self.assertNotIn(b"bitbucket-pipelines", body)
        finally:
            Path(apk_path).unlink(missing_ok=True)


class HttpFlowTests(unittest.TestCase):
    """Tests the upload -> poll -> fetch flow with urlopen mocked."""

    def _temp_apk(self) -> str:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"fake-apk-bytes")
            return f.name

    def test_upload_scan_returns_scan_id(self):
        apk_path = self._temp_apk()
        try:
            with patch("urllib.request.urlopen", return_value=_http_response({"scan_id": "abc123"})):
                scan_id = malimite_ci.upload_scan(
                    "http://x", "key", apk_path,
                    llm_enabled=False, assessment_enabled=True, timeout=5)
            self.assertEqual(scan_id, "abc123")
        finally:
            Path(apk_path).unlink(missing_ok=True)

    def test_upload_scan_missing_scan_id_raises(self):
        apk_path = self._temp_apk()
        try:
            with patch("urllib.request.urlopen", return_value=_http_response({})):
                with self.assertRaises(malimite_ci.MalimiteCiError) as cm:
                    malimite_ci.upload_scan("http://x", "key", apk_path, False, True, 5)
            self.assertEqual(cm.exception.exit_code, 3)
        finally:
            Path(apk_path).unlink(missing_ok=True)

    def test_poll_scan_returns_on_done(self):
        with patch("urllib.request.urlopen",
                    return_value=_http_response({"state": "done", "exit_code": 0})):
            detail = malimite_ci.poll_scan("http://x", "key", "s1", poll_interval=0.01, overall_timeout=5)
        self.assertEqual(detail["state"], "done")

    def test_poll_scan_raises_on_error_state(self):
        with patch("urllib.request.urlopen",
                    return_value=_http_response({"state": "error", "exit_code": 1})):
            with self.assertRaises(malimite_ci.MalimiteCiError) as cm:
                malimite_ci.poll_scan("http://x", "key", "s1", poll_interval=0.01, overall_timeout=5)
        self.assertEqual(cm.exception.exit_code, 4)

    def test_poll_scan_raises_on_timeout(self):
        with patch("urllib.request.urlopen",
                    return_value=_http_response({"state": "running"})):
            with self.assertRaises(malimite_ci.MalimiteCiError) as cm:
                malimite_ci.poll_scan("http://x", "key", "s1", poll_interval=0.01, overall_timeout=0.05)
        self.assertEqual(cm.exception.exit_code, 4)

    def test_fetch_vulnerabilities_returns_list(self):
        with patch("urllib.request.urlopen", return_value=_http_response([_vuln("HIGH")])):
            vulns = malimite_ci.fetch_vulnerabilities("http://x", "key", "s1")
        self.assertEqual(len(vulns), 1)

    def test_http_error_raises_with_exit_code_3(self):
        err = urllib.error.HTTPError("http://x", 404, "Not Found", {}, io.BytesIO(b'{"detail":"nope"}'))
        try:
            with patch("urllib.request.urlopen", side_effect=err):
                with self.assertRaises(malimite_ci.MalimiteCiError) as cm:
                    malimite_ci.fetch_vulnerabilities("http://x", "key", "missing-scan")
            self.assertEqual(cm.exception.exit_code, 3)
            self.assertIn("nope", str(cm.exception))
        finally:
            err.close()

    def test_connection_error_raises_with_exit_code_3(self):
        err = urllib.error.URLError("connection refused")
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(malimite_ci.MalimiteCiError) as cm:
                malimite_ci.fetch_vulnerabilities("http://x", "key", "s1")
        self.assertEqual(cm.exception.exit_code, 3)


class MainEndToEndTests(unittest.TestCase):
    """Drives main() with urlopen mocked end to end, asserting on the process exit code."""

    def _run_main(self, responses, extra_args):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"fake apk bytes")
            apk_path = f.name
        try:
            mock = MagicMock(side_effect=[_http_response(r) for r in responses])
            with patch("urllib.request.urlopen", mock):
                return malimite_ci.main([
                    "--url", "http://x", "--api-key", "k",
                    "--file", apk_path, *extra_args,
                ])
        finally:
            Path(apk_path).unlink(missing_ok=True)

    def test_exits_1_when_fail_on_threshold_met(self):
        code = self._run_main(
            responses=[
                {"scan_id": "s1"},                    # upload
                {"state": "done"},                     # poll
                [_vuln("HIGH")],                       # vulnerabilities
            ],
            extra_args=["--fail-on", "HIGH"],
        )
        self.assertEqual(code, 1)

    def test_exits_0_when_no_finding_meets_threshold(self):
        code = self._run_main(
            responses=[
                {"scan_id": "s1"},
                {"state": "done"},
                [_vuln("LOW")],
            ],
            extra_args=["--fail-on", "HIGH"],
        )
        self.assertEqual(code, 0)

    def test_exits_2_when_file_missing(self):
        code = malimite_ci.main([
            "--url", "http://x", "--api-key", "k",
            "--file", "/does/not/exist.apk", "--fail-on", "HIGH",
        ])
        self.assertEqual(code, 2)

    def test_json_out_written_with_correct_shape(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = str(Path(tmpdir) / "result.json")
            code = self._run_main(
                responses=[
                    {"scan_id": "s1"},
                    {"state": "done"},
                    [_vuln("HIGH"), _vuln("MEDIUM")],
                ],
                extra_args=["--fail-on", "HIGH", "--json-out", json_out],
            )
            self.assertEqual(code, 1)
            with open(json_out) as f:
                summary = json.load(f)
            self.assertEqual(summary["scan_id"], "s1")
            self.assertEqual(summary["verdict"], "fail")
            self.assertEqual(summary["severity_counts"], {"HIGH": 1, "MEDIUM": 1})


class SlackPayloadTests(unittest.TestCase):
    """build_slack_payload() — pure function, no network."""

    def test_payload_includes_fail_verdict(self):
        payload = malimite_ci.build_slack_payload(
            "scan-123", "http://x/#/scan/scan-123", "app.apk", "HIGH", True,
            {"HIGH": 2}, 2)
        text = json.dumps(payload)
        self.assertIn("FAIL", text)
        self.assertIn("app.apk", text)
        self.assertIn("scan-123"[:8], text)

    def test_payload_includes_pass_verdict(self):
        payload = malimite_ci.build_slack_payload(
            "scan-123", "http://x/#/scan/scan-123", "app.apk", "HIGH", False,
            {}, 0)
        text = json.dumps(payload)
        self.assertIn("pass", text)
        self.assertIn("No active findings", text)

    def test_payload_includes_ci_context_when_present(self):
        payload = malimite_ci.build_slack_payload(
            "scan-123", "http://x/#/scan/scan-123", "app.apk", "HIGH", False, {}, 0,
            ci_pipeline_url="https://bitbucket.org/org/repo/pipelines/results/42",
            ci_triggered_by="bitbucket-pipelines")
        text = json.dumps(payload)
        self.assertIn("Pipeline run", text)
        self.assertIn("bitbucket-pipelines", text)

    def test_long_filename_does_not_exceed_slacks_150_char_header_limit(self):
        """Slack's header block REJECTS the entire message (not just truncates) if its
        plain_text exceeds 150 chars — a long APK/IPA filename must not silently drop the
        notification, which is the one thing this feature exists to guarantee."""
        long_filename = "a" * 140 + ".apk"
        payload = malimite_ci.build_slack_payload(
            "scan-123", "http://x/#/scan/scan-123", long_filename, "HIGH", False, {}, 0)
        header_text = payload["blocks"][0]["text"]["text"]
        self.assertLessEqual(len(header_text), 150)

    def test_payload_omits_ci_context_when_absent(self):
        payload = malimite_ci.build_slack_payload(
            "scan-123", "http://x/#/scan/scan-123", "app.apk", "HIGH", False, {}, 0)
        text = json.dumps(payload)
        self.assertNotIn("Pipeline run", text)
        self.assertNotIn("Triggered by", text)


class SlackDeliveryTests(unittest.TestCase):
    """send_slack_notification() network behavior — the critical property under test is that a
    delivery failure NEVER raises or otherwise propagates into the caller's exit code; it is
    always best-effort."""

    def test_successful_post_sends_expected_body(self):
        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["body"] = json.loads(req.data)
            seen["content_type"] = req.headers.get("Content-type")
            return _http_response({"ok": True})

        with patch("urllib.request.urlopen", fake_urlopen):
            malimite_ci.send_slack_notification("https://hooks.slack.com/services/x", {"blocks": []})

        self.assertEqual(seen["url"], "https://hooks.slack.com/services/x")
        self.assertEqual(seen["body"], {"blocks": []})
        self.assertEqual(seen["content_type"], "application/json")

    def test_http_error_does_not_raise(self):
        err = urllib.error.HTTPError("https://hooks.slack.com/x", 404, "Not Found", {}, io.BytesIO(b"no_service"))
        try:
            with patch("urllib.request.urlopen", side_effect=err):
                malimite_ci.send_slack_notification("https://hooks.slack.com/services/x", {"blocks": []})
            # reaching here without an exception is the assertion
        finally:
            err.close()

    def test_connection_error_does_not_raise(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            malimite_ci.send_slack_notification("https://hooks.slack.com/services/x", {"blocks": []})
            # reaching here without an exception is the assertion


class SlackIntegrationInMainTests(unittest.TestCase):
    """Exercises --slack-webhook-url end to end through main(), confirming the single most
    important property: a Slack delivery failure must never change the process exit code — the
    --fail-on verdict computed from the scan itself is the only thing allowed to do that."""

    def _run_main_with_slack(self, scan_responses, slack_urlopen_side_effect, extra_args):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"fake apk bytes")
            apk_path = f.name
        try:
            scan_mocks = [_http_response(r) for r in scan_responses]
            call_count = {"n": 0}

            def urlopen_router(req, timeout=None):
                call_count["n"] += 1
                if call_count["n"] <= len(scan_mocks):
                    return scan_mocks[call_count["n"] - 1]
                # the call after all scan-flow calls is the Slack POST
                if callable(slack_urlopen_side_effect):
                    return slack_urlopen_side_effect(req)
                raise slack_urlopen_side_effect

            with patch("urllib.request.urlopen", urlopen_router):
                return malimite_ci.main([
                    "--url", "http://x", "--api-key", "k", "--file", apk_path,
                    "--slack-webhook-url", "https://hooks.slack.com/services/x", *extra_args,
                ])
        finally:
            Path(apk_path).unlink(missing_ok=True)

    def test_slack_delivery_failure_does_not_change_a_passing_exit_code(self):
        code = self._run_main_with_slack(
            scan_responses=[{"scan_id": "s1"}, {"state": "done"}, [_vuln("LOW")]],
            slack_urlopen_side_effect=urllib.error.URLError("slack is down"),
            extra_args=["--fail-on", "HIGH"],
        )
        self.assertEqual(code, 0)

    def test_slack_delivery_failure_does_not_change_a_failing_exit_code(self):
        code = self._run_main_with_slack(
            scan_responses=[{"scan_id": "s1"}, {"state": "done"}, [_vuln("HIGH")]],
            slack_urlopen_side_effect=urllib.error.URLError("slack is down"),
            extra_args=["--fail-on", "HIGH"],
        )
        self.assertEqual(code, 1)

    def test_slack_is_notified_even_when_fail_on_is_none(self):
        """The core scenario this feature exists for: monitoring mode (--fail-on NONE) still
        gets the security team a notification for every scan, pass or fail."""
        notified = {}

        def capture(req):
            notified["body"] = json.loads(req.data)
            return _http_response({"ok": True})

        code = self._run_main_with_slack(
            scan_responses=[{"scan_id": "s1"}, {"state": "done"}, [_vuln("HIGH")]],
            slack_urlopen_side_effect=capture,
            extra_args=["--fail-on", "NONE"],
        )
        self.assertEqual(code, 0)   # NONE never fails the build
        self.assertIn("blocks", notified["body"])   # but Slack was still notified

    def test_no_slack_call_when_webhook_url_not_set(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"fake apk bytes")
            apk_path = f.name
        try:
            mock = MagicMock(side_effect=[
                _http_response({"scan_id": "s1"}),
                _http_response({"state": "done"}),
                _http_response([_vuln("LOW")]),
            ])
            with patch("urllib.request.urlopen", mock):
                malimite_ci.main(["--url", "http://x", "--api-key", "k", "--file", apk_path,
                                  "--fail-on", "HIGH"])
            self.assertEqual(mock.call_count, 3)   # upload, poll, vulnerabilities — no 4th (Slack) call
        finally:
            Path(apk_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
