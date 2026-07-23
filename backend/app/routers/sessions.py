from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List
from backend.app.database.mongodb import get_database
from backend.app.middleware.auth_middleware import get_current_user
from backend.app.models.schemas import SessionResponse

router = APIRouter(prefix="/api/sessions", tags=["Sessions"])

@router.get("", response_model=List[SessionResponse])
async def list_sessions(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    protocol: str = Query(None),
    threat_level: str = Query(None),
    username: str = Depends(get_current_user)
):
    """Retrieves paginated attacker sessions, optionally filtered by protocol or severity."""
    db = get_database()
    if db is None:
        return []
        
    query = {}
    if protocol:
        query["protocol"] = protocol
    if threat_level:
        query["threat_level"] = threat_level
        
    cursor = db.sessions.find(query).sort("start_time", -1).skip(offset).limit(limit)
    sessions = await cursor.to_list(length=limit)
    return sessions

@router.get("/{session_id}", response_model=SessionResponse)
async def session_details(session_id: str, username: str = Depends(get_current_user)):
    """Retrieves a single session including credentials tried, commands, and AI explanations."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database connection failed")
        
    session = await db.sessions.find_one({"session_id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    return session
