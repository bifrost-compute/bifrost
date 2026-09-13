#!/usr/bin/env python3
"""Offline scan helper for governed environments (#58).

The environment scan verdict is a RECORDED FIELD: Bifrost's control plane
does not scan anything itself. An administrator runs this script against an
environment's exact content — trivy on the base image, pip-audit on the
pinned package list — and pastes the emitted JSON fragment into the
environment's `scan` field in the policy document, then applies it with
PUT /settings/policy (the catalog is admin-only, section-replace):

    # 1. Scan the catalog entry "ml-base" in the current policy document:
    curl -s -H "Authorization: Bearer $TOKEN" $BIFROST/api/v1/settings/policy > policy.json
    scripts/scan-environment.py policy.json ml-base
    # 2. Paste the emitted fragment as ml-base's "scan" value (see --write),
    #    then PUT the edited document back:
    curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        --data @policy.json $BIFROST/api/v1/settings/policy

There is no PATCH for a single catalog entry; the PUT above replaces the
sections the document carries, so send back everything GET returned (minus
the provenance "source" key).

With --write the script edits the policy document in place (sets the
environment's "scan" to the fresh verdict) so step 2 is just the PUT.

Verdict rules:
  - trivy reports no HIGH/CRITICAL vulnerabilities in the base image AND
    pip-audit reports no known vulnerabilities in the pinned packages
    -> status "clean".
  - Any finding -> status "failed"; the findings are printed on stderr so
    the administrator can fix the content and re-scan.
  - A scanner that cannot run at all is an error (exit 2), never a verdict
    — a scan that did not happen must not be recorded as either outcome.

An environment with no base image and no packages has nothing to scan; the
verdict is "clean" with the scanner named so the admission gate's audit
trail shows who attested it.

Requires: trivy (https://trivy.dev) when a base image is set, pip-audit
(https://pypi.org/project/pip-audit) when packages are set. Neither is a
control-plane dependency; install them where the administrator runs this.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

PINNED = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9][A-Za-z0-9.!+_-]*$")


def fail(msg):
    print(f"scan-environment: error: {msg}", file=sys.stderr)
    sys.exit(2)


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kw)
    except FileNotFoundError:
        fail(f"{cmd[0]} is not installed; the offline scan workflow needs it (see the script header)")


def tool_version(cmd, flag="--version"):
    out = run(cmd + [flag])
    line = (out.stdout or out.stderr).strip().splitlines()
    return line[0].split()[-1] if line else "unknown"


def find_environment(policy, name):
    """Locate `name` in a policy document: the GET /settings/policy body
    (environments under "environments") or a bare environments list."""
    envs = policy.get("environments") if isinstance(policy, dict) else policy
    if not isinstance(envs, list):
        fail("policy document carries no environments list")
    for env in envs:
        if env.get("name") == name:
            return env
    fail(f"no environment named {name!r} in the policy document")


def scan_image(image):
    """trivy on the base image; returns (findings, scanner-name)."""
    out = run(["trivy", "image", "--quiet", "--scanners", "vuln",
               "--severity", "HIGH,CRITICAL", "--format", "json", image])
    if out.returncode not in (0, 1):
        fail(f"trivy could not scan {image}: {out.stderr.strip() or out.stdout.strip()}")
    findings = []
    for result in json.loads(out.stdout or "{}").get("Results") or []:
        findings.extend(result.get("Vulnerabilities") or [])
    return findings, f"trivy {tool_version(['trivy'])}"


def scan_packages(packages):
    """pip-audit over the pinned requirements; returns (findings, scanner-name)."""
    for pkg in packages:
        if not PINNED.match(pkg):
            fail(f"package {pkg!r} is not pinned to an exact version (name==version); the catalog would refuse it")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", prefix="requirements-", delete=False) as f:
        f.write("\n".join(packages) + "\n")
        reqs = f.name
    out = run(["pip-audit", "--requirement", reqs, "--progress-spinner", "off", "--format", "json"])
    if out.returncode not in (0, 1):
        fail(f"pip-audit could not scan the package list: {out.stderr.strip() or out.stdout.strip()}")
    findings = []
    for dep in json.loads(out.stdout or "{}").get("dependencies") or []:
        for v in dep.get("vulns") or []:
            findings.append(f'{v.get("id", "?")} {dep.get("name", "?")}=={dep.get("version", "?")}')
    return findings, f"pip-audit {tool_version(['pip-audit'])}"


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("policy", help="policy document JSON (the GET /settings/policy body, or a bare environments list)")
    p.add_argument("environment", help="catalog name of the environment to scan")
    p.add_argument("--write", action="store_true",
                   help="write the fresh verdict into the policy document in place (then PUT it back)")
    args = p.parse_args()

    with open(args.policy) as f:
        policy = json.load(f)
    env = find_environment(policy, args.environment)

    findings, scanners = [], []
    if env.get("base_image"):
        found, scanner = scan_image(env["base_image"])
        findings += [f'{v.get("VulnerabilityID", "?")} {v.get("PkgName", "?")}' for v in found]
        scanners.append(scanner)
    if env.get("packages"):
        found, scanner = scan_packages(env["packages"])
        findings += found
        scanners.append(scanner)

    verdict = {
        "status": "failed" if findings else "clean",
        "scanner": " + ".join(scanners) if scanners else "scan-environment.py (nothing to scan)",
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if findings:
        print(f"scan-environment: {len(findings)} finding(s) against {args.environment}:", file=sys.stderr)
        for f_ in findings:
            print(f"  {f_}", file=sys.stderr)

    if args.write:
        env["scan"] = verdict
        with open(args.policy, "w") as f:
            json.dump(policy, f, indent=2)
            f.write("\n")
        print(f"scan-environment: wrote verdict {verdict['status']!r} into {args.policy}; PUT it back to apply", file=sys.stderr)
    else:
        json.dump(verdict, sys.stdout, indent=2)
        print()
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
