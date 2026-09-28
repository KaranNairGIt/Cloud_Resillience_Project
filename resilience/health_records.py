"""Local read-only clinical demo store; excludes source encounter/patient IDs."""

from __future__ import annotations

import csv
from contextlib import closing
from pathlib import Path
import sqlite3
import uuid


FIELDS = (
    "race", "gender", "age", "admission_type_id", "discharge_disposition_id",
    "admission_source_id", "time_in_hospital", "num_lab_procedures",
    "num_procedures", "num_medications", "number_outpatient", "number_emergency",
    "number_inpatient", "diag_1", "diag_2", "diag_3", "number_diagnoses", "readmitted",
)


def database_path(project_root: Path | None = None) -> Path:
    root = project_root or Path(__file__).resolve().parent.parent
    return root / "data" / "clinical.db"


def import_public_encounters(project_root: Path | None = None) -> dict:
    root = project_root or Path(__file__).resolve().parent.parent
    csv_path = root / "data" / "raw" / "diabetic_data.csv"
    db_path = database_path(root)
    if not csv_path.is_file():
        raise FileNotFoundError("Run `python -m resilience.cli dataset fetch` first")
    if db_path.exists():
        check = sqlite3.connect(db_path)
        try:
            id_type = next((row[2] for row in check.execute(
                "PRAGMA table_info(encounters)") if row[1] == "demo_id"), None)
        finally:
            check.close()
        if id_type == "TEXT":
            return health_summary(root)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    staging = db_path.with_suffix(".building")
    if staging.exists():
        staging.unlink()
    columns = ", ".join(f'"{field}" TEXT' for field in FIELDS)
    placeholders = ",".join("?" for _ in range(len(FIELDS) + 1))
    db = sqlite3.connect(staging)
    try:
        db.execute(f"CREATE TABLE encounters (demo_id TEXT PRIMARY KEY, {columns})")
        with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            missing = set(FIELDS) - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"clinical CSV is missing columns: {sorted(missing)}")
            sql = f"INSERT INTO encounters VALUES ({placeholders})"
            batch = []
            for row in reader:
                # The demo surrogate key is generated locally. Source encounter_id and
                # patient_nbr are intentionally discarded and never enter this store.
                batch.append((uuid.uuid4().hex, *(row[field] for field in FIELDS)))
                if len(batch) == 2000:
                    db.executemany(sql, batch)
                    batch.clear()
            if batch:
                db.executemany(sql, batch)
        db.execute("CREATE INDEX idx_encounter_readmitted ON encounters(readmitted)")
        db.commit()
    finally:
        db.close()
    staging.replace(db_path)
    return health_summary(root)


def health_summary(project_root: Path | None = None) -> dict:
    db_path = database_path(project_root)
    if not db_path.is_file():
        return {"loaded": False, "encounters": 0, "readmission": {}}
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    # closing() releases the file handle; `with connect()` alone only ends the transaction.
    with closing(sqlite3.connect(uri, uri=True)) as db:
        count = db.execute("SELECT COUNT(*) FROM encounters").fetchone()[0]
        readmission = dict(db.execute(
            "SELECT readmitted, COUNT(*) FROM encounters GROUP BY readmitted ORDER BY readmitted"
        ).fetchall())
        ages = dict(db.execute(
            "SELECT age, COUNT(*) FROM encounters GROUP BY age ORDER BY age"
        ).fetchall())
    return {
        "loaded": True,
        "encounters": count,
        "readmission": readmission,
        "age_bands": ages,
        "source_ids_removed": True,
        "display_policy": "aggregate counts only; individual encounter rows are never exposed by the dashboard",
    }
