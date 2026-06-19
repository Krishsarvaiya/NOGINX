import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from auth_utils import decode_access_token
from database import User, get_db

security = HTTPBearer(auto_error=False)


def _service_token() -> str:
    return os.getenv("NOGINX_SERVICE_TOKEN", "")


def _service_user() -> str:
    return os.getenv("NOGINX_SERVICE_USER", "watcher")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    username = decode_access_token(credentials.credentials)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


def get_user_or_service(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    header_token = (
        request.headers.get("X-Service-Token")
        or request.headers.get("x-service-token")
    )
    if not header_token and credentials:
        header_token = credentials.credentials

    token = _service_token()
    service_user = _service_user()
    if header_token and token and header_token.strip() == token.strip():
        user = db.query(User).filter(User.username == service_user).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    f"Service user '{service_user}' not found. "
                    "Restart the API after setting NOGINX_SERVICE_TOKEN."
                ),
            )
        return user

    return get_current_user(credentials, db)
