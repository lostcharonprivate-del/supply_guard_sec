"""Capability discovery: what this instance can scan and what it can detect.

The false-positive and false-negative notes are served from the same place the
detectors declare them, so the UI can show a finding's known limitations next to
the finding itself rather than burying them in a README nobody reads.
"""

from __future__ import annotations

from fastapi import APIRouter

from supplyguard.api.schemas import DetectorInfo, EcosystemInfo
from supplyguard.detectors.base import all_detectors
from supplyguard.detectors.reference_sets import available_reference_sets
from supplyguard.ecosystems import all_adapters

router = APIRouter(tags=["meta"])


@router.get("/detectors", response_model=list[DetectorInfo])
async def list_detectors() -> list[DetectorInfo]:
    return [DetectorInfo(**detector.describe()) for detector in all_detectors()]


@router.get("/ecosystems", response_model=list[EcosystemInfo])
async def list_ecosystems() -> list[EcosystemInfo]:
    reference_sets = available_reference_sets()
    return [
        EcosystemInfo(
            name=adapter.name,
            display_name=adapter.display_name,
            manifest_patterns=list(adapter.manifest_patterns),
            lockfile_patterns=list(adapter.lockfile_patterns),
            supports_scopes=adapter.supports_scopes,
            download_metric=adapter.download_metric,
            reference_set_size=reference_sets.get(adapter.name, 0),
        )
        for adapter in all_adapters()
    ]
