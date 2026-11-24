"""Local assessment persistence. Never stores API credentials or request headers."""

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class AssessmentStore:
    def __init__(self, directory):
        directory = Path(directory).expanduser()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "assessments.sqlite3"
        if self.path.is_symlink():
            raise ValueError("The assessment database must not be a symlink.")
        descriptor = (
            os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            if not self.path.exists()
            else None
        )
        if descriptor is not None:
            os.close(descriptor)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY, mode TEXT NOT NULL, target TEXT NOT NULL,
                created_at TEXT NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL,
                report TEXT)""")
            if "authorization" not in {
                row[1] for row in db.execute("PRAGMA table_info(assessments)")
            }:
                db.execute("ALTER TABLE assessments ADD COLUMN authorization TEXT")
            db.execute(
                "UPDATE assessments SET status='error', progress='Interrupted by a previous server shutdown. Start a new assessment.' WHERE status IN ('queued','running')"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, identifier, mode, target, created_at, authorization=None):
        with self.connect() as db:
            db.execute(
                "INSERT INTO assessments VALUES (?,?,?,?,?,?,NULL,?)",
                (
                    identifier,
                    mode,
                    target,
                    created_at,
                    "queued",
                    "Waiting for the local collection worker",
                    json.dumps(authorization) if authorization else None,
                ),
            )

    def update(self, identifier, status, progress, report=None):
        with self.connect() as db:
            if "authorization" not in {
                row[1] for row in db.execute("PRAGMA table_info(assessments)")
            }:
                db.execute("ALTER TABLE assessments ADD COLUMN authorization TEXT")
            db.execute(
                "UPDATE assessments SET status=?, progress=?, report=? WHERE id=?",
                (
                    status,
                    progress,
                    json.dumps(report, ensure_ascii=True)
                    if report is not None
                    else None,
                    identifier,
                ),
            )

    @staticmethod
    def decode(row):
        if row is None:
            return None
        result = dict(
            zip(
                (
                    "id",
                    "mode",
                    "target",
                    "created_at",
                    "status",
                    "progress",
                    "report",
                    "authorization",
                ),
                row,
            )
        )
        result["report"] = json.loads(result["report"]) if result["report"] else None
        result["authorization"] = (
            json.loads(result["authorization"]) if result["authorization"] else None
        )
        return result

    def get(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            return None
        with self.connect() as db:
            return self.decode(
                db.execute(
                    "SELECT * FROM assessments WHERE id=?", (identifier,)
                ).fetchone()
            )

    def list(self):
        with self.connect() as db:
            return [
                self.decode(row)
                for row in db.execute(
                    "SELECT * FROM assessments ORDER BY created_at DESC LIMIT 100"
                )
            ]

    def pending(self):
        with self.connect() as db:
            return db.execute(
                "SELECT count(*) FROM assessments WHERE status IN ('queued','running')"
            ).fetchone()[0]

    def delete(self, identifier):
        with self.connect() as db:
            db.execute(
                "DELETE FROM assessments WHERE id=? AND status NOT IN ('queued','running')",
                (identifier,),
            )


@contextmanager
def dashboard_lock(directory):
    """Keep two local server processes from interrupting the same job history."""
    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / ".dashboard.lock"
    if path.is_symlink():
        raise ValueError("Dashboard lock must not be a symlink.")
    descriptor = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    stream = os.fdopen(descriptor, "r+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise ValueError(
                    "Another dashboard is using this data directory."
                ) from None
        else:
            import fcntl

            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ValueError(
                    "Another dashboard is using this data directory."
                ) from None
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()
