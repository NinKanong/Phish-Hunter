from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.version import APP_VERSION
router=APIRouter(prefix="/health",tags=["health"])
@router.get("")
def health(db:Session=Depends(get_session)):
    db.execute(text("SELECT 1"))
    return {"status":"ok","service":"phishhunter","version":APP_VERSION,"database":"ok","architecture":"v22-unified"}
