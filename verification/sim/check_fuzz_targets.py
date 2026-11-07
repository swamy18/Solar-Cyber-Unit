"""Check that the CI fuzz list and the registered fuzz targets agree.

A target that exists but is not in the CI loop is a target nobody ever runs,
and the deliverable codec target was exactly that for a while. This script is
the check, so the drift cannot come back unnoticed.
"""

import re
import sys
from pathlib import Path

# Repository root: this script lives in `verification/sim/`, while `fuzz/`
# and `.github/` live at the repo root, so the root is two levels up —
# unlike the vector scripts, whose `tests/vectors` sibling moved along.
ROOT = Path(__file__).resolve().parents[2]


def registered_targets() -> list:
    out = []
    in_bin = False
    for line in (ROOT / "fuzz" / "Cargo.toml").read_text().splitlines():
        if line.strip() == "[[bin]]":
            in_bin = True
            continue
        if in_bin:
            m = re.match(r'name = "([a-z_0-9]+)"', line.strip())
            if m:
                out.append(m.group(1))
                in_bin = False
    return out


def ci_targets() -> list:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    m = re.search(r"for t in (.+?) do", text, re.S)
    if not m:
        return []
    return [t.strip(";,") for t in m.group(1).split() if t.strip(";,")]


def main() -> int:
    reg = registered_targets()
    ci = ci_targets()
    missing = sorted(set(reg) - set(ci))
    extra = sorted(set(ci) - set(reg))
    print(f"registered targets: {len(reg)}")
    print(f"ci smoke list     : {len(ci)}")
    if missing:
        print(f"NOT in the CI loop: {', '.join(missing)}")
    if extra:
        print(f"in CI but not registered: {', '.join(extra)}")
    if missing or extra:
        return 1
    print("every registered target runs in CI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
