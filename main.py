import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError, ExpiredSignatureError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import User,Token, UserPermission
import pathlib
import time
import os
from uuid import uuid4
from typing import Optional, Dict, Any
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

# =====================================================
# FastAPI Application
# =====================================================
app = FastAPI(title="FastAPI Auth with PostgreSQL + JWT (RS256)")

# Static & Templates
app.mount("/static", StaticFiles(directory="./static"), name="static")
templates = Jinja2Templates(directory="./templates")

# Database
Base.metadata.create_all(bind=engine)

# =====================================================
# Security & JWT Setup
# =====================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PRIVATE_KEY = pathlib.Path("./private.pem").read_text()
PUBLIC_KEY = pathlib.Path("./public.pem").read_text()
ALGORITHM = "RS256"

# JWT Config
ISSUER = os.getenv("JWT_ISSUER", "myblogapp.com")
AUDIENCE = os.getenv("JWT_AUDIENCE", "myblogapp_users")
ACCESS_TOKEN_EXP_MIN = int(os.getenv("ACCESS_TOKEN_EXP_MIN", "15"))
REFRESH_TOKEN_EXP_DAYS = int(os.getenv("REFRESH_TOKEN_EXP_DAYS", "30"))

# In-memory revocation (for production: use Redis/DB)
_revoked_jtis = set()
_valid_refresh_jtis = set()


# =====================================================
# Utility Functions
# =====================================================
def _now_ts() -> int:
    return int(time.time())

# Order matters: first item is default for new hashes.
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    # Argon2 has no 72-byte limit; just hash the raw password.
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ---------------- JWT Creation ----------------
def create_access_token_for_user(
    *, user: User, db: Session,extra: Optional[Dict[str, Any]] = None, expires_minutes: Optional[int] = None
) -> Dict[str, Any]:
    iat = _now_ts()
    expires = datetime.utcnow() + timedelta(minutes=expires_minutes or ACCESS_TOKEN_EXP_MIN)
    jti = str(uuid4())

    payload = {
        "iss": ISSUER,
        "sub": f"user_{user.id}",
        "aud": AUDIENCE,
        "iat": iat,
        "nbf": iat,
        "exp": expires,
        "jti": jti,
        "type": "access",
        "user_id": user.id,
        "email": getattr(user, "email", None),
        "role": getattr(user, "role", "user"),
        "name": getattr(user, "name", user.username),
        "permissions": [perm.permission for perm in getattr(user, "permissions", [])] or ["read_post"],
    }

    if extra:
        payload.update(extra)

    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    token_rec = Token(user_id=user.id, jti=jti, token_type="access", expires_at=expires)
    db.add(token_rec)
    db.commit()
    return {"token": token, "jti": jti, "exp": expires}


def create_refresh_token_for_user(
    *, user: User, db: Session,expires_days: Optional[int] = None
) -> Dict[str, Any]:
    iat = _now_ts()
    expires = datetime.utcnow() + timedelta(days=expires_days or REFRESH_TOKEN_EXP_DAYS)
    jti = str(uuid4())

    payload = {
        "iss": ISSUER,
        "sub": f"user_{user.id}",
        "aud": AUDIENCE,
        "iat": iat,
        "nbf": iat,
        "exp": expires,
        "jti": jti,
        "type": "refresh",
        "user_id": user.id,
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    token_rec = Token(user_id=user.id, jti=jti, token_type="refresh", expires_at=expires)
    db.add(token_rec)
    db.commit()
    _valid_refresh_jtis.add(jti)  # store refresh JTI
    return {"token": token, "jti": jti, "exp": expires}


# ---------------- JWT Verification ----------------
def verify_jwt_token_strict(token: str, *, check_audience: bool = True, check_issuer: bool = True):
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        decode_kwargs = {"algorithms": [ALGORITHM]}
        if check_audience:
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM], audience=AUDIENCE)
        else:
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {str(e)}")

    if check_issuer and payload.get("iss") != ISSUER:
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    jti = payload.get("jti")
    if jti in _revoked_jtis:
        raise HTTPException(status_code=401, detail="Token revoked")

    return payload


# =====================================================
# Routes
# =====================================================

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post("/register")
def register_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(username=username, hashed_password=get_password_hash(password))
    db.add(user)
    db.commit()

    # Optionally add default permissions
    db.add(UserPermission(user_id=user.id, permission="create_post"))
    db.add(UserPermission(user_id=user.id, permission="edit_post"))
    db.commit()
    return RedirectResponse(url="/", status_code=302)


@app.post("/login")
def login_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access = create_access_token_for_user(user=user,db=db)
    refresh = create_refresh_token_for_user(user=user,db=db)

    response = RedirectResponse(url="/protected", status_code=302)
    response.set_cookie("access_token", access["token"], httponly=True, secure=False, samesite="lax")
    response.set_cookie("refresh_token", refresh["token"], httponly=True, secure=False, samesite="lax")
    return response


@app.get("/protected", response_class=HTMLResponse)
def protected(request: Request, authorization: str | None = Header(default=None)):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    else:
        token = request.cookies.get("access_token")

    if not token:
        return RedirectResponse(url="/", status_code=302)

    payload = verify_jwt_token_strict(token)
    username = payload.get("name") or payload.get("email") or f"user_{payload.get('user_id')}"
    return templates.TemplateResponse("protected.html", {"request": request, "username": username})


# =====================================================
# Refresh Token Endpoint
# =====================================================
@app.post("/token/refresh")
def refresh_token(request: Request, db: Session = Depends(get_db)):
    refresh_token = (
        request.cookies.get("refresh_token")
        or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    )
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    payload = verify_jwt_token_strict(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    old_jti = payload.get("jti")
    if old_jti not in _valid_refresh_jtis:
        raise HTTPException(status_code=401, detail="Refresh token invalid or revoked")

    # Revoke old refresh token
    _valid_refresh_jtis.discard(old_jti)
    _revoked_jtis.add(old_jti)

    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_access = create_access_token_for_user(user=user)
    new_refresh = create_refresh_token_for_user(user=user)

    response = JSONResponse(
        {"message": "Token refreshed", "access_token": new_access["token"], "refresh_token": new_refresh["token"]}
    )
    response.set_cookie("access_token", new_access["token"], httponly=True, secure=False, samesite="lax")
    response.set_cookie("refresh_token", new_refresh["token"], httponly=True, secure=False, samesite="lax")
    return response


# =====================================================
# Logout Endpoint
# =====================================================
@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    access_token = request.cookies.get("access_token")
    if refresh_token:
        try:
            ref_payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[ALGORITHM], audience=AUDIENCE)
            access_payload = jwt.decode(access_token, PUBLIC_KEY, algorithms=[ALGORITHM], audience=AUDIENCE)
            ref_jti = ref_payload.get("jti")
            access_jti = access_payload.get("jti")
            db_token_ref = db.query(Token).filter(Token.jti == ref_jti).first()
            db_token_access = db.query(Token).filter(Token.jti == access_jti).first()
            if db_token_ref:
                db_token_ref.revoked = True
                db.commit()
            if db_token_access:
                db_token_access.revoked = True
                db.commit()
        except Exception:
            pass

    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp

# ---------------- Admin: Token panel (admin only) ----------------
@app.get("/admin/tokens", response_class=HTMLResponse)
def admin_tokens(request: Request, db: Session = Depends(get_db)):
    # simple admin auth from cookie token
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/", status_code=302)

    payload = verify_jwt_token_strict(token)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    # show all tokens (optionally filter by user query param)
    user_q = request.query_params.get("user")
    if user_q:
        users = db.query(User).filter((User.username == user_q) | (User.email == user_q) | (User.id == user_q)).all()
        if users:
            user_ids = [u.id for u in users]
            tokens = db.query(Token).filter(Token.user_id.in_(user_ids)).order_by(Token.created_at.desc()).all()
        else:
            tokens = []
    else:
        tokens = db.query(Token).order_by(Token.created_at.desc()).limit(200).all()

    return templates.TemplateResponse("admin_tokens.html", {"request": request, "tokens": tokens})

@app.post("/admin/revoke")
def admin_revoke(token_jti: str = Form(...), request: Request = None, db: Session = Depends(get_db)):
    # require admin
    cookie = request.cookies.get("access_token")
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = verify_jwt_token_strict(cookie)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    db_token = db.query(Token).filter(Token.jti == token_jti).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    db_token.revoked = True
    db.commit()
    return RedirectResponse(url="/admin/tokens", status_code=302)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Redirect for 404 or 405
    if exc.status_code in [404, 405]:
        return RedirectResponse(url="/", status_code=302)
    # Let other HTTP errors behave normally
    return RedirectResponse(url="/", status_code=302)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, StarletteHTTPException) and exc.status_code in [404, 405]:
        return RedirectResponse(url="/", status_code=302)
    # Log other exceptions for debugging
    print(f"Unexpected error: {exc}")
    return RedirectResponse(url="/", status_code=302)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, StarletteHTTPException) and exc.status_code in [404, 405]:
        return RedirectResponse(url="/", status_code=302)
    # Log other exceptions for debugging
    print(f"Unexpected error: {exc}")
    return RedirectResponse(url="/", status_code=302)

if __name__ =="__main__":
    uvicorn.run(app,host="127.0.0.1",port=8000)