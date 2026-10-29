from pathlib import Path

from packaging.requirements import Requirement

from scripts.lock_sam import normalize


def test_freeze_preserves_windows_dependency_only_on_windows():
    text = normalize("aws-sam-cli==1.170.0\npywin32==312\n")
    requirement = Requirement(text.splitlines()[1])
    assert requirement.marker is not None
    assert requirement.marker.evaluate({"sys_platform": "win32"})
    assert not requirement.marker.evaluate({"sys_platform": "linux"})
    assert not requirement.marker.evaluate({"sys_platform": "darwin"})
    pinned = [
        Requirement(line)
        for line in Path("requirements-sam.lock").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    windows = next(r for r in pinned if r.name == "pywin32")
    assert windows.marker is not None
    assert not windows.marker.evaluate({"sys_platform": "linux"})
