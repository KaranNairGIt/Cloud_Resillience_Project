"""Safe local downloader/validator for the public UCI diabetes encounter dataset."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile


DATASET_ID = 296
DATASET_NAME = "Diabetes 130-US Hospitals for Years 1999-2008"
DATASET_URL = (
    "https://archive.ics.uci.edu/static/public/296/"
    "diabetes%2B130-us%2Bhospitals%2Bfor%2Byears%2B1999-2008.zip"
)
ATTRIBUTION = (
    "Clore, J., Cios, K., DeShazo, J., & Strack, B. (2014). Diabetes 130-US Hospitals "
    "for Years 1999-2008 [Dataset]. UCI Machine Learning Repository. "
    "https://doi.org/10.24432/C5230J. Licensed under CC BY 4.0."
)
EXPECTED_FILES = {"diabetic_data.csv", "IDS_mapping.csv"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_csv_bytes(archive: zipfile.ZipFile, member: str) -> bytes:
    # Select named members without extracting arbitrary archive paths.
    matches = [name for name in archive.namelist() if Path(name).name.lower() == member.lower()]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {member} in UCI archive; found {len(matches)}")
    return archive.read(matches[0])


def validate_dataset_archive(blob: bytes) -> tuple[bytes, bytes, int]:
    """Validate ZIP integrity, expected schema, and encounter count before writing."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            if archive.testzip() is not None:
                raise ValueError("UCI archive failed its CRC check")
            present = {Path(name).name for name in archive.namelist()}
            missing = EXPECTED_FILES - present
            if missing:
                raise ValueError(f"UCI archive is missing required files: {sorted(missing)}")
            records = _safe_csv_bytes(archive, "diabetic_data.csv")
            mapping = _safe_csv_bytes(archive, "IDS_mapping.csv")
    except zipfile.BadZipFile as exc:
        raise ValueError("Downloaded file is not a valid ZIP archive") from exc

    reader = csv.DictReader(records.decode("utf-8-sig").splitlines())
    required = {"encounter_id", "patient_nbr", "race", "gender", "age", "readmitted"}
    missing_columns = required - set(reader.fieldnames or [])
    if missing_columns:
        raise ValueError(f"UCI clinical CSV is missing columns: {sorted(missing_columns)}")
    row_count = sum(1 for _ in reader)
    if row_count != 101766:
        raise ValueError(f"Expected 101766 encounters from UCI, found {row_count}")
    return records, mapping, row_count


def download_dataset(project_root: Path | None = None) -> dict:
    root = project_root or Path(__file__).resolve().parent.parent
    raw_dir = root / "data" / "raw"
    records_path = raw_dir / "diabetic_data.csv"
    mapping_path = raw_dir / "IDS_mapping.csv"
    manifest_path = raw_dir / "manifest.json"
    if records_path.exists() and mapping_path.exists() and manifest_path.exists():
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    request = urllib.request.Request(DATASET_URL, headers={"User-Agent": "CyberResilienceCapstone/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"UCI download failed with HTTP {response.status}")
        blob = response.read(25_000_001)
    if len(blob) > 25_000_000:
        raise ValueError("UCI archive exceeded the 25 MB download limit")
    records, mapping, row_count = validate_dataset_archive(blob)

    raw_dir.mkdir(parents=True, exist_ok=True)
    records_path.write_bytes(records)
    mapping_path.write_bytes(mapping)
    manifest = {
        "dataset_id": DATASET_ID,
        "name": DATASET_NAME,
        "source_url": DATASET_URL,
        "retrieved_utc": datetime.now(timezone.utc).isoformat(),
        "license": "CC BY 4.0",
        "attribution": ATTRIBUTION,
        "records_file": records_path.name,
        "records_sha256": _sha256(records),
        "mapping_file": mapping_path.name,
        "mapping_sha256": _sha256(mapping),
        "encounter_rows": row_count,
        "privacy_note": "Publicly released real-world encounter data; contains fields UCI flags as potentially sensitive. Keep local, do not publish raw records, and do not expose direct identifiers in the demo.",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
