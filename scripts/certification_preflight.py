"""Local-only preflight for a Windows certification operator.

The script does not load secret values, authenticate, resolve DNS, contact a
target, or authorize a test.  A failure means the operator must stop.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

CAPABILITY_VARIABLES = {
    "asrep-roast-validation": {"ADAF_RT_LAB_ASREP_ROASTABLE_USER", "ADAF_RT_LAB_ASREP_PREAUTH_USER"},
    "kerberoast-validation": {"ADAF_RT_LAB_KERBEROAST_SPN", "ADAF_RT_LAB_KERBEROAST_MISSING_SPN", "KRB5CCNAME"},
    "dcsync-rights-validation": {"ADAF_RT_LAB_BIND_USER", "ADAF_RT_LAB_TARGET_PRINCIPAL", "ADAF_RT_LAB_EXPECTED"},
    "laps-read-authorization": {"ADAF_RT_LAB_BIND_USER", "ADAF_RT_LAB_TARGET_PRINCIPAL", "ADAF_RT_LAB_LAPS_COMPUTER_DN", "ADAF_RT_LAB_EXPECTED"},
    "gmsa-read-authorization": {"ADAF_RT_LAB_BIND_USER", "ADAF_RT_LAB_TARGET_PRINCIPAL", "ADAF_RT_LAB_GMSA_DN", "ADAF_RT_LAB_EXPECTED"},
    "zerologon-detection": {"ADAF_RT_LAB_ZEROLOGON_TARGET", "ADAF_RT_LAB_EXPECTED"},
}


def check(passed: bool, name: str, detail: str) -> bool:
    print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only ADAF-RedTeam certification preflight")
    parser.add_argument("--env-file", default=".env.lab.ps1")
    parser.add_argument("--capability", choices=sorted(CAPABILITY_VARIABLES))
    args = parser.parse_args()
    failures = False
    print("ADAF-RedTeam certification preflight (no target contact)")

    launcher = shutil.which("py")
    if launcher is None:
        failures |= not check(False, "python-launcher", "The Windows 'py' launcher was not found. Ask the approved software administrator to install Python 3.10 or later.")
    else:
        version = subprocess.run([launcher, "-3", "--version"], text=True, capture_output=True)
        failures |= not check(version.returncode == 0, "python-launcher", (version.stdout or version.stderr).strip())

    failures |= not check(Path("pyproject.toml").is_file(), "project-folder", "Run this script from the ADAF-RedTeam repository folder.")
    failures |= not check(Path("docs/CERTIFICATION.md").is_file(), "certification-policy", "docs/CERTIFICATION.md found")

    env_file = Path(args.env_file)
    if not env_file.is_file():
        failures |= not check(False, "lab-environment-file", f"Missing {env_file}. Do not create it from guesswork; ask the lab administrator for the approved values.")
    else:
        content = env_file.read_text(encoding="utf-8")
        names = set(re.findall(r"^\s*\$env:([A-Z0-9_]+)\s*=", content, re.MULTILINE))
        required = {"ADAF_RT_LAB", "ADAF_RT_LAB_DOMAIN", "ADAF_RT_LAB_DC", "ADAF_RT_LAB_SOURCE_ADDR"}
        if args.capability:
            required |= CAPABILITY_VARIABLES[args.capability]
        missing = sorted(required - names)
        detail = f"Missing variable names: {', '.join(missing)}. Values were not displayed." if missing else "Required variable names found; values were not displayed."
        failures |= not check(not missing, "lab-environment-file", detail)
        lab_opt_in = re.search(r"^\s*\$env:ADAF_RT_LAB\s*=\s*['\"]?1['\"]?\s*(?:#.*)?$", content, re.MULTILINE)
        failures |= not check(lab_opt_in is not None, "lab-opt-in", "ADAF_RT_LAB is set to the required value; the value was not displayed")

    git = shutil.which("git")
    if git is None:
        failures |= not check(False, "secret-file-ignore", "Git was not found, so .gitignore could not be checked. Ask the project administrator to verify it.")
    else:
        ignored = subprocess.run([git, "check-ignore", "-q", "--", ".env.lab.ps1"], capture_output=True).returncode == 0
        failures |= not check(ignored, "secret-file-ignore", ".env.lab.ps1 must be ignored by Git")

    if failures:
        print("\nSTOP: Preflight failed. Do not run a live certification test. Give this entire output to the lab administrator.")
        return 1
    print("\nPASS: Local preflight complete. This does not authorize or start a live test. Continue only with the named lab administrator and reviewer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
