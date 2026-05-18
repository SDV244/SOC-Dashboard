from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from backend.auth import (
    _COOKIE, _verify_token,
    list_users, create_user, delete_user, reset_password,
)

router = APIRouter(prefix="/api/admin/users", tags=["users"])


def _require_admin(request: Request) -> dict:
    raw_cookie = request.headers.get("cookie", "")
    token = None
    for part in raw_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{_COOKIE}="):
            token = part[len(f"{_COOKIE}="):]
            break
    user = _verify_token(token) if token else None
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    return user


class CreateUserBody(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class ResetPasswordBody(BaseModel):
    new_password: str


@router.get("")
def get_users(request: Request):
    _require_admin(request)
    return list_users()


@router.post("")
def add_user(body: CreateUserBody, request: Request):
    _require_admin(request)
    try:
        return create_user(body.username, body.password, body.is_admin)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{user_id}")
def remove_user(user_id: int, request: Request):
    admin = _require_admin(request)
    try:
        delete_user(user_id, admin["username"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"deleted": user_id}


@router.put("/{user_id}/reset-password")
def change_password(user_id: int, body: ResetPasswordBody, request: Request):
    _require_admin(request)
    try:
        reset_password(user_id, body.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"updated": user_id}
