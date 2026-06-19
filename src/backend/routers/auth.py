"""Authentication endpoints for the High School Management System API."""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from ..database import teachers_collection, verify_password
from ..session_store import create_session, revoke_session, validate_session

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

bearer_auth = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


def get_current_teacher(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_auth)
) -> Dict[str, Any]:
    """Resolve and return the current authenticated teacher from a bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Authentication required")

    username = validate_session(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    teacher = teachers_collection.find_one({"_id": username})
    if not teacher:
        raise HTTPException(status_code=401, detail="Invalid session")

    return teacher


@router.post("/login")
def login(payload: LoginRequest) -> Dict[str, Any]:
    """Login a teacher account"""
    # Find the teacher in the database
    teacher = teachers_collection.find_one({"_id": payload.username})

    # Verify password using Argon2 verifier from database.py
    if not teacher or not verify_password(teacher.get("password", ""), payload.password):
        raise HTTPException(
            status_code=401, detail="Invalid username or password")

    token = create_session(teacher["username"])

    # Return teacher information and session token
    return {
        "token": token,
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }


@router.get("/check-session")
def check_session(teacher: Dict[str, Any] = Depends(get_current_teacher)) -> Dict[str, Any]:
    """Check whether the bearer token maps to a valid teacher session."""
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_auth)
) -> Dict[str, str]:
    """Invalidate the current bearer token session."""
    if credentials and credentials.credentials:
        revoke_session(credentials.credentials)
    return {"message": "Logged out"}
