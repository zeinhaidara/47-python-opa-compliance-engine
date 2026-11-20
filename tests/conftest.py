import os
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def opa() -> str:
    # The pinned opa must be present; a missing binary fails, never skips.
    path = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not path:
        pytest.fail("opa not found: set OPA_BIN or put the pinned opa on PATH")
    return path
