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
      - run: echo hello
""" % SHA


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


if __name__ == "__main__":
    unittest.main()
