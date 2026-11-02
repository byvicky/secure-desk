import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from securedesk import database
from securedesk.config import settings
from securedesk.schemas import (
    Category,
    Priority,
    Status,
    TicketAssignment,
    TicketCommentCreate,
    TicketCreate,
    TicketOut,
    TicketUpdate,
)
from securedesk.security import (
    RateLimiter,
    get_current_user,
    hash_password,
    redact_sensitive_data,
    require_admin,
    verify_csrf,
    verify_password,
)
from securedesk.triage import analyze

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securedesk")
limiter = RateLimiter(settings.rate_limit)
login_limiter = RateLimiter(limit=5, window_seconds=900)


class LoginRequest(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserActiveRequest(BaseModel):
    active: bool


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="agent", pattern=r"^(admin|agent)$")


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.production and len(settings.session_secret) < 32:
        raise RuntimeError(
            "SECUREDESK_SESSION_SECRET deve ter pelo menos 32 caracteres em produção."
        )
    database.initialize()
    if settings.admin_password:
        database.ensure_bootstrap_admin(settings.admin_username, hash_password(settings.admin_password))
    yield


app = FastAPI(
    title="SecureDesk API",
    description="API de triagem segura de solicitações de suporte.",
    version="0.2.0",
    docs_url=None if settings.production else "/docs",
    redoc_url=None if settings.production else "/redoc",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret or "development-session-secret-change-me",
    session_cookie="securedesk_session",
    max_age=8 * 60 * 60,
    same_site="strict",
    https_only=settings.production,
)
app.mount("/static", StaticFiles(directory="web"), name="static")

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:64]
    client = request.client.host if request.client else "unknown"
    if not limiter.check(client):
        return JSONResponse(status_code=429, content={"detail": "Limite de requisições excedido."},
                            headers={"Retry-After": "60", "X-Request-ID": request_id})
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Erro interno request_id=%s", request_id)
        response = JSONResponse(status_code=500, content={"detail": "Erro interno do servidor."})
    response.headers.update({
        "X-Request-ID": request_id,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    })
    return response


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SecureDesk"}


@app.get("/api/session")
def session_status(request: Request):
    user = request.session.get("user")
    authenticated = bool(user and user.get("id") and user.get("role"))
    if not settings.production and not settings.web_password and not settings.admin_password:
        return {"authenticated": True, "user": {"username": "local-dev", "role": "admin"}}
    return {"authenticated": authenticated, "user": user if authenticated else None, "csrf_token": request.session.get("csrf_token") if authenticated else None}


@app.post("/api/login")
def login(payload: LoginRequest, request: Request):
    origin = request.headers.get("origin")
    if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(status_code=403, detail="Origem da solicitação inválida.")
    client_ip = request.client.host if request.client else "unknown"
    attempt_key = f"{client_ip}:{payload.username.casefold()}"
    if not login_limiter.check(attempt_key):
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 15 minutos.")
    user = database.get_user_by_username(payload.username)
    if not user and payload.username == settings.admin_username and settings.web_password and secrets.compare_digest(payload.password, settings.web_password):
        database.ensure_bootstrap_admin(settings.admin_username, hash_password(settings.web_password))
        user = database.get_user_by_username(settings.admin_username)
    if not user or not user["active"] or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")
    login_limiter.reset(attempt_key)
    request.session.clear()
    request.session["user"] = {"id": user["id"], "username": user["username"], "role": user["role"]}
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    return {"authenticated": True, "user": request.session["user"], "csrf_token": request.session["csrf_token"]}


@app.post("/api/logout")
def logout(request: Request, _: None = Depends(verify_csrf)):
    request.session.clear()
    return {"authenticated": False}


@app.get("/api/users", dependencies=[Depends(require_admin)])
def users():
    return database.list_users()


@app.patch("/api/users/{user_id}/active", dependencies=[Depends(require_admin), Depends(verify_csrf)])
def update_user_active(user_id: int, payload: UserActiveRequest,
                       actor: Annotated[dict, Depends(get_current_user)]):
    result, error = database.set_user_active(user_id, payload.active, actor["id"])
    if error == "not_found":
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if error == "self":
        raise HTTPException(status_code=400, detail="Você não pode desativar sua própria conta.")
    if error == "last_admin":
        raise HTTPException(status_code=409, detail="Não é possível desativar o último administrador ativo.")
    return result


@app.get("/api/dashboard/stats", dependencies=[Depends(get_current_user)])
def dashboard_stats():
    return database.ticket_stats()


@app.post("/api/users", status_code=201, dependencies=[Depends(require_admin), Depends(verify_csrf)])
def create_user(payload: UserCreate):
    try:
        return database.create_user(payload.username, hash_password(payload.password), payload.role)
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="Nome de usuário já cadastrado.") from exc
        raise


@app.post("/api/tickets", response_model=TicketOut, status_code=status.HTTP_201_CREATED,
          dependencies=[Depends(get_current_user), Depends(verify_csrf)])
def submit_ticket(payload: TicketCreate, user: Annotated[dict, Depends(get_current_user)]):
    title = redact_sensitive_data(payload.title)
    description = redact_sensitive_data(payload.description)
    requester = redact_sensitive_data(payload.requester)
    category, priority = analyze(title, description, payload.category)
    return database.create_ticket({"requester": requester, "title": title, "description": description,
                                   "category": category, "priority": priority}, actor=user)


@app.get("/api/tickets", response_model=list[TicketOut], dependencies=[Depends(get_current_user)])
def tickets(limit: int = Query(default=50, ge=1, le=100),
            search: str | None = Query(default=None, min_length=1, max_length=100),
            status_filter: Annotated[Status | None, Query(alias="status")] = None,
            category: Category | None = None, priority: Priority | None = None):
    return database.list_tickets(limit, status_filter, category, priority, search)


@app.get("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(get_current_user)])
def ticket_detail(ticket_id: int):
    result = database.get_ticket(ticket_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/api/tickets/{ticket_id}/history", dependencies=[Depends(get_current_user)])
def ticket_history(ticket_id: int):
    if database.get_ticket(ticket_id) is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return database.get_ticket_history(ticket_id)


@app.patch("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(get_current_user), Depends(verify_csrf)])
def change_ticket_status(ticket_id: int, payload: TicketUpdate, user: Annotated[dict, Depends(get_current_user)]):
    result = database.update_status(ticket_id, payload.status, actor=user)
    if result is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/api/users/assignable", dependencies=[Depends(get_current_user)])
def assignable_users():
    return database.list_assignable_users()


@app.post("/api/tickets/{ticket_id}/assignment", dependencies=[Depends(get_current_user), Depends(verify_csrf)])
def assign_ticket(ticket_id: int, payload: TicketAssignment, user: Annotated[dict, Depends(get_current_user)]):
    result = database.assign_ticket(ticket_id, payload.user_id, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Chamado ou usuário ativo não encontrado.")
    return result


@app.get("/api/tickets/{ticket_id}/comments", dependencies=[Depends(get_current_user)])
def ticket_comments(ticket_id: int):
    if database.get_ticket(ticket_id) is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return database.list_comments(ticket_id)


@app.post("/api/tickets/{ticket_id}/comments", status_code=201, dependencies=[Depends(get_current_user), Depends(verify_csrf)])
def add_ticket_comment(ticket_id: int, payload: TicketCommentCreate, user: Annotated[dict, Depends(get_current_user)]):
    comment = database.add_comment(ticket_id, redact_sensitive_data(payload.body), user)
    if comment is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return comment


@app.get("/", include_in_schema=False)
def home():
    return FileResponse("web/index.html")
