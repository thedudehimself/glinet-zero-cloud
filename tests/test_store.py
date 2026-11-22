from pathlib import Path
from store import StateStore


def test_persists_and_hydrates_across_restarts(tmp_path: Path):
    db = tmp_path / "state.db"
    s1 = StateStore(db)
    s1.upsert_device_status(
        "rm1pe",
        {"ip": "10.10.20.15", "vlan": "vlan20", "online": True, "fw": "V1.10.0 release1", "cloud_enabled": False},
    )
    s1.record_sweep(
        "rm1pe",
        {
            "timestamp": "2026-11-22T10:00:00Z",
            "exit_code": 0,
            "status": "clean",
            "verdict": "CLEAN",
            "summary": {"IOC": 0, "PERSIST": 0, "REVIEW": 1, "INFO": 0},
            "output": "ok",
        },
    )
    s1.save_conntrack_alerts([], "2026-11-22T10:00:05Z")

    s2 = StateStore(db)
    statuses = s2.get_all_device_statuses()
    assert statuses["rm1pe"]["fw"] == "V1.10.0 release1"
    assert s2.get_latest_sweeps()["rm1pe"]["verdict"] == "CLEAN"
    assert s2.get_conntrack_snapshot() == {"checked_at": "2026-11-22T10:00:05Z", "alerts": []}


def test_trims_sweep_history_to_latest_20(tmp_path: Path):
    s = StateStore(tmp_path / "state.db")
    for i in range(25):
        s.record_sweep(
            "rm1pe",
            {
                "timestamp": f"2026-11-22T10:00:{i:02d}Z",
                "exit_code": 0,
                "status": "clean",
                "verdict": f"RUN-{i}",
                "summary": {"IOC": 0},
                "output": f"out-{i}",
            },
        )
    history = s.get_sweep_history("rm1pe", limit=30)
    assert len(history) == 20
    assert history[0]["verdict"] == "RUN-24"
    assert history[-1]["verdict"] == "RUN-5"
