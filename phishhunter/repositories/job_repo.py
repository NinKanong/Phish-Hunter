from sqlalchemy.orm import Session
from phishhunter.models import AnalysisJob, Artifact, CaseArtifact, CaseScan

class JobRepository:
    def __init__(self, db: Session): self.db = db
    def get(self, job_id: str): return self.db.query(AnalysisJob).filter_by(job_id=job_id).first()
    def list_for_user(self, user_id: int): return self.db.query(AnalysisJob).filter_by(owner_user_id=user_id).order_by(AnalysisJob.id.desc()).limit(200).all()
    def create(self, **kwargs):
        row=AnalysisJob(**kwargs); self.db.add(row); self.db.flush(); return row
    def artifacts(self, job_id: str): return self.db.query(Artifact).filter_by(job_id=job_id).order_by(Artifact.id.asc()).all()
    def add_artifact(self, **kwargs):
        row=Artifact(**kwargs); self.db.add(row); self.db.flush(); return row
    def link_case(self, case_id: int, artifact_id: int):
        if not self.db.query(CaseArtifact).filter_by(case_id=case_id, artifact_id=artifact_id).first():
            self.db.add(CaseArtifact(case_id=case_id, artifact_id=artifact_id))
    def link_scan(self, case_id: int, scan_id: int):
        if not self.db.query(CaseScan).filter_by(case_id=case_id, scan_id=scan_id).first():
            self.db.add(CaseScan(case_id=case_id, scan_id=scan_id))
