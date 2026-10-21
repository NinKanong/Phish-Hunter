from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import secrets
import uuid
from typing import Any

from .orchestrator import analyze_artifacts
from .schema import ArtifactInput
from phishhunter.db.database import SessionLocal
from phishhunter.models import AnalysisJob, Artifact, IOC, Scan, User, UserActivity


@dataclass
class Job:
    id: str
    status: str = "queued"
    progress: int = 0
    message: str = "Queued"
    artifacts: list[ArtifactInput] = field(default_factory=list)
    blobs: dict[str, bytes] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    phase_history: list[dict[str, Any]] = field(default_factory=list)
    owner_user_id: int | None = None
    guest_id: str | None = None
    access_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    subscribers: set[asyncio.Queue] = field(default_factory=set)

    async def publish(self, progress: int, message: str, status: str | None = None):
        now = datetime.now(timezone.utc)
        self.progress = max(0, min(100, int(progress)))
        self.message = message
        if self.started_at:
            started = datetime.fromisoformat(self.started_at)
            self.duration_seconds = max(0.0, (now - started).total_seconds())
        self.phase_history.append({"timestamp": now.isoformat(), "progress": self.progress, "message": message, "status": status or self.status, "elapsed_seconds": self.duration_seconds})
        self.phase_history = self.phase_history[-200:]
        if status:
            self.status = status
        payload = {
            "job_id": self.id,
            "status": self.status,
            "progress": self.progress,
            "message": message,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
        }
        for queue in list(self.subscribers):
            await queue.put(payload)


class JobStore:
    def __init__(self):
        self.jobs: dict[str, Job] = {}

    def create(
        self,
        artifacts: list[ArtifactInput],
        blobs: dict[str, bytes],
        *,
        owner_user_id: int | None = None,
        guest_id: str | None = None,
    ) -> Job:
        job = Job(
            id=uuid.uuid4().hex,
            artifacts=artifacts,
            blobs=blobs,
            owner_user_id=owner_user_id,
            guest_id=guest_id,
        )
        self.jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job:
        if job_id not in self.jobs:
            raise KeyError(job_id)
        return self.jobs[job_id]

    async def run(self, job: Job):
        job.started_at = datetime.now(timezone.utc).isoformat()
        job.completed_at = None
        job.duration_seconds = 0.0
        await job.publish(1, "Starting network-artifact triage", "running")
        loop = asyncio.get_running_loop()
        updates: asyncio.Queue = asyncio.Queue()
        done = asyncio.Event()

        def callback(percent: int, message: str):
            loop.call_soon_threadsafe(updates.put_nowait, (percent, message))

        async def reporter():
            while not done.is_set():
                try:
                    percent, message = await asyncio.wait_for(updates.get(), timeout=0.5)
                    await job.publish(percent, message)
                except asyncio.TimeoutError:
                    pass

        report_task = asyncio.create_task(reporter())
        try:
            result = await asyncio.to_thread(
                analyze_artifacts,
                job.artifacts,
                job.blobs,
                callback,
                job.id,
            )
            job.result = result
            job.completed_at = datetime.now(timezone.utc).isoformat()
            if job.started_at:
                job.duration_seconds = max(0.0, (datetime.fromisoformat(job.completed_at) - datetime.fromisoformat(job.started_at)).total_seconds())

            # Persist every authenticated network investigation automatically.
            # The previous UI required the analyst to click a separate Save button,
            # which meant a completed scan could disappear from Dashboard/Workbench
            # even though the investigation itself had completed successfully.
            if job.owner_user_id is not None:
                db = SessionLocal()
                try:
                    user = db.get(User, job.owner_user_id)
                    if user:
                        # Keep one durable AnalysisJob row synchronized with the
                        # in-memory job state used by the live forensic UI.
                        job_row = db.query(AnalysisJob).filter(AnalysisJob.job_id == job.id).first()
                        if job_row:
                            job_row.status = "completed"
                            job_row.progress = 100
                            job_row.message = "Investigation complete"
                            job_row.result = result or {}
                            job_row.started_at = datetime.fromisoformat(job.started_at) if job.started_at else None
                            job_row.completed_at = datetime.fromisoformat(job.completed_at) if job.completed_at else None
                            job_row.duration_seconds = int(round(job.duration_seconds or 0))

                        # The upload endpoint already persisted the artifact rows.
                        # Create a durable Scan automatically so Dashboard and the
                        # private Workbench immediately show the completed history.
                        existing = db.query(Scan).filter(
                            Scan.owner_user_id == user.id
                        ).order_by(Scan.id.desc()).all()
                        scan = next((row for row in existing if isinstance(row.result, dict) and
                                     ((row.result.get("case_metadata") or {}).get("case_id") == job.id)), None)
                        if scan is None:
                            filenames = [a.filename for a in job.artifacts]
                            scan_result = dict(result or {})
                            metadata = dict(scan_result.get("case_metadata") or {})
                            metadata.update({
                                "case_id": job.id,
                                "job_id": job.id,
                                "source": "network-artifacts",
                                "filenames": filenames,
                            })
                            scan_result["case_metadata"] = metadata
                            scan_result["source_files"] = filenames
                            scan = Scan(
                                tenant_id=user.tenant_id,
                                owner_user_id=user.id,
                                scan_type="pcap",
                                target=", ".join(filenames)[:10000] or f"network-artifacts:{job.id}",
                                status="completed",
                                verdict=str(scan_result.get("verdict", "unknown")),
                                risk_score=int(scan_result.get("risk_score", 0) or 0),
                                result=scan_result,
                            )
                            db.add(scan)
                            db.flush()
                            for kind, values in (scan_result.get("iocs") or {}).items():
                                if isinstance(values, list):
                                    for value in values[:5000]:
                                        text = str(value).strip()
                                        if text:
                                            db.add(IOC(tenant_id=user.tenant_id, owner_user_id=user.id, kind=str(kind), value=text, source_scan_id=scan.id))
                            db.add(UserActivity(
                                user_id=user.id, event_type="analysis", action="scan.created",
                                detail=f"Created network investigation scan #{scan.id} from {len(filenames)} artifact(s)",
                                success=True, metadata_json={"scan_id": scan.id, "job_id": job.id, "filenames": filenames},
                            ))
                            job.result = scan_result
                        if job_row:
                            job_row.result = job.result or {}
                        db.commit()
                except Exception:
                    db.rollback()
                    # The live investigation must still complete even if persistence
                    # encounters a transient database problem. The user can retry the
                    # save endpoint, while the forensic result remains available here.
                finally:
                    db.close()

            await job.publish(100, "Investigation complete", "completed")
        except Exception as exc:
            job.completed_at = datetime.now(timezone.utc).isoformat()
            if job.started_at:
                job.duration_seconds = max(0.0, (datetime.fromisoformat(job.completed_at) - datetime.fromisoformat(job.started_at)).total_seconds())
            job.error = f"{type(exc).__name__}: {exc}"
            if job.owner_user_id is not None:
                db = SessionLocal()
                try:
                    job_row = db.query(AnalysisJob).filter(AnalysisJob.job_id == job.id).first()
                    if job_row:
                        job_row.status = "failed"
                        job_row.progress = int(job.progress or 0)
                        job_row.message = job.error
                        job_row.error = job.error
                        job_row.completed_at = datetime.fromisoformat(job.completed_at) if job.completed_at else None
                        job_row.duration_seconds = int(round(job.duration_seconds or 0))
                        db.commit()
                except Exception:
                    db.rollback()
                finally:
                    db.close()
            await job.publish(job.progress, job.error, "failed")
        finally:
            done.set()
            await report_task


JOB_STORE = JobStore()
