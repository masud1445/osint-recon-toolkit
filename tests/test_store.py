"""Local storage lifecycle and process isolation."""

import pytest

from osint_recon.store import dashboard_lock


def test_dashboard_lock_prevents_concurrent_servers(tmp_path):
    with dashboard_lock(tmp_path):
        with pytest.raises(ValueError, match="Another dashboard"):
            with dashboard_lock(tmp_path):
                raise AssertionError("Second process lock must not succeed")
    with dashboard_lock(tmp_path):
        pass
