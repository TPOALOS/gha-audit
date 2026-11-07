import contextlib
import io
import json
import os
import tempfile
import unittest

import gha_audit as ga

SHA = "a" * 40

GOOD = """name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s
        with:
          persist-credentials: false
      - run: echo hello
""" % SHA
BARE = GOOD.replace("        with:\n          persist-credentials: false\n", "")


def rules(text):
    return {(f[0], f[1]) for f in ga.audit_text(text)}


class AuditTests(unittest.TestCase):
    def test_good_workflow_clean(self):
        self.assertEqual(ga.audit_text(GOOD), [])

    def test_unpinned_levels(self):
        t = GOOD + "      - uses: actions/setup-python@v5\n      - uses: acme/tool@v1\n      - uses: acme/other@main\n      - uses: acme/bare\n"
        r = rules(t)
        self.assertIn(("LOW", "unpinned-action"), r)
        self.assertIn(("MEDIUM", "unpinned-action"), r)
        self.assertIn(("HIGH", "unpinned-action"), r)

    def test_local_and_docker_skipped(self):
        t = GOOD + "      - uses: ./local-action\n      - uses: docker://alpine:3\n"
        self.assertEqual(ga.audit_text(t), [])

    def test_missing_and_write_all_permissions(self):
        self.assertIn(("MEDIUM", "missing-permissions"),
                      rules("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ls\n"))
        self.assertIn(("HIGH", "write-all-permissions"), rules(GOOD.replace("contents: read", "write-all").replace("permissions:\n  write-all", "permissions: write-all")))

    def test_job_level_permissions_accepted(self):
        t = "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: x\n    steps:\n      - run: ls\n"
        self.assertNotIn(("MEDIUM", "missing-permissions"), rules(t))

    def test_script_injection_inline_and_block(self):
        inline = GOOD + "      - run: echo ${{ github.event.pull_request.title }}\n"
        block = GOOD + "      - run: |\n          echo start\n          echo \"${{ github.event.issue.body }}\"\n"
        for t in (inline, block):
            self.assertIn(("HIGH", "script-injection"), rules(t))

    def test_safe_env_pattern_not_flagged(self):
        t = GOOD + "      - run: echo \"$TITLE\"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n"
        self.assertNotIn(("HIGH", "script-injection"), rules(t))

    def test_expression_outside_run_block_not_flagged(self):
        t = GOOD + "      - name: x\n        if: github.event.pull_request.title != ''\n        run: |\n          echo ok\n      - name: y\n        with:\n          t: ${{ github.event.issue.title }}\n"
        self.assertNotIn(("HIGH", "script-injection"), rules(t))

    def test_pull_request_target_checkout(self):
        t = ("on:\n  pull_request_target:\n    types: [opened]\npermissions:\n  contents: read\njobs:\n  a:\n"
             "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s\n        with:\n"
             "          ref: ${{ github.event.pull_request.head.sha }}\n" % SHA)
        self.assertIn(("HIGH", "pull-request-target-checkout"), rules(t))
        self.assertNotIn(("HIGH", "pull-request-target-checkout"), rules(t.replace("pull_request_target", "pull_request")))

    def test_secret_curl_unsecure_selfhosted(self):
        t = ("on:\n  pull_request:\npermissions:\n  contents: read\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"
             "jobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n"
             "      - run: curl -s https://example.com/install.sh | bash\n"
             "      - run: deploy --token ${{ secrets.TOKEN }}\n")
        r = rules(t)
        for expected in (("MEDIUM", "curl-pipe-shell"), ("LOW", "secret-in-command"),
                         ("HIGH", "unsecure-commands"), ("MEDIUM", "self-hosted-on-pr")):
            self.assertIn(expected, r)

    def test_comments_ignored(self):
        t = GOOD + "      # - uses: acme/tool@main\n"
        self.assertEqual(ga.audit_text(t), [])


class CliTests(unittest.TestCase):
    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            wf = os.path.join(d, "ci.yml")
            with open(wf, "w") as fh:
                fh.write(GOOD)
            self.assertEqual(ga.main([d]), 0)
            with open(wf, "w") as fh:
                fh.write(GOOD + "      - uses: acme/tool@main\n")
            self.assertEqual(ga.main([wf]), 1)
            self.assertEqual(ga.main([os.path.join(d, "nope.yml")]), 2)


def checkout_text(extra=""):
    return BARE.replace("      - uses: actions/checkout@%s\n" % SHA, "      - uses: actions/checkout@%s\n%s" % (SHA, extra))


class PersistCredentialsTests(unittest.TestCase):
    def test_flagged_without_persist_false(self):
        self.assertIn(("LOW", "checkout-persist-credentials"), rules(BARE))

    def test_not_flagged_with_persist_false(self):
        t = checkout_text("        with:\n          persist-credentials: false\n")
        self.assertNotIn("checkout-persist-credentials", {r for _, r in rules(t)})

    def test_persist_false_of_another_step_does_not_count(self):
        t = (checkout_text() + "      - uses: actions/cache@%s\n        with:\n          persist-credentials: false\n" % SHA)
        self.assertIn("checkout-persist-credentials", {r for _, r in rules(t)})

    def test_checkout_not_first_key_in_step(self):
        t = BARE.replace("      - uses: actions/checkout@%s\n" % SHA,
                         "      - name: get code\n        uses: actions/checkout@%s\n        with:\n          persist-credentials: false\n" % SHA)
        self.assertNotIn("checkout-persist-credentials", {r for _, r in rules(t)})


class IgnoreTests(unittest.TestCase):
    BAD = GOOD + "      - uses: acme/tool@main  # gha-audit: ignore\n"

    def test_line_ignore_all(self):
        self.assertNotIn("unpinned-action", {r for _, r in rules(self.BAD)})

    def test_line_ignore_specific_rule(self):
        t = GOOD + "      - uses: acme/tool@main  # gha-audit: ignore[unpinned-action]\n"
        self.assertNotIn("unpinned-action", {r for _, r in rules(t)})

    def test_line_ignore_other_rule_does_not_silence(self):
        t = GOOD + "      - uses: acme/tool@main  # gha-audit: ignore[script-injection]\n"
        self.assertIn("unpinned-action", {r for _, r in rules(t)})

    def test_ignore_only_affects_its_own_line(self):
        t = self.BAD + "      - uses: acme/other@main\n"
        self.assertEqual(sum(1 for f in ga.audit_text(t) if f[1] == "unpinned-action"), 1)

    def test_ignore_file(self):
        t = "# gha-audit: ignore-file[missing-permissions,checkout-persist-credentials]\n" + BARE.replace(
            "permissions:\n  contents: read\n", "")
        self.assertEqual(rules(t), set())

    def test_ignore_file_all(self):
        self.assertEqual(rules("# gha-audit: ignore-file\n" + GOOD + "      - uses: acme/x@main\n"), set())


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ga.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FormatTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._t.name, "ci.yml")
        with open(self.path, "w") as fh:
            fh.write(GOOD + "      - uses: acme/tool@main\n")

    def tearDown(self):
        self._t.cleanup()

    def test_json(self):
        code, out, _ = run_main(self.path, "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIn("unpinned-action", {d["rule"] for d in data})
        self.assertEqual({"severity", "rule", "file", "line", "message", "fix"}, set(data[0]))

    def test_sarif_structure(self):
        _, out, _ = run_main(self.path, "--format", "sarif")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "gha-audit")
        res = [r for r in run["results"] if r["ruleId"] == "unpinned-action"][0]
        self.assertEqual(res["level"], "error")
        self.assertGreaterEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertIn("unpinned-action", {r["id"] for r in run["tool"]["driver"]["rules"]})

    def test_sarif_clean_is_valid_and_exit_zero(self):
        with open(self.path, "w") as fh:
            fh.write(GOOD)
        code, out, _ = run_main(self.path, "--format", "sarif")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["runs"][0]["results"], [])

    def test_text_unchanged(self):
        code, out, err = run_main(self.path)
        self.assertEqual(code, 1)
        self.assertIn("fix:", out)
        self.assertIn("finding(s)", err)

    def test_min_severity_applies_to_json(self):
        _, out, _ = run_main(self.path, "--format", "json", "--min-severity", "HIGH")
        self.assertTrue(all(d["severity"] == "HIGH" for d in json.loads(out)))


if __name__ == "__main__":
    unittest.main()
