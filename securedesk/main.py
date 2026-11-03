import logging
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
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
    rate_limit_bucket,
    redact_sensitive_data,
    require_admin,
    verify_csrf,
    verify_password,
)
from securedesk.triage import analyze

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securedesk")
rate_limit_db = f"{settings.database}.ratelimit"
limiter = RateLimiter(settings.rate_limit, storage_path=rate_limit_db)
login_limiter = RateLimiter(limit=5, window_seconds=900, storage_path=rate_limit_db)


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies before FastAPI parses or buffers them."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            # Delegate disconnect detection to the real ASGI server after replaying
            # the buffered body; do not synthesize an early disconnect.
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send):
        body = b'{"detail":"Corpo da requisicao excede o limite permitido."}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})


class LoginRequest(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserActiveRequest(BaseModel):
    active: bool = Field(strict=True)


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
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.max_request_body_bytes)
app.mount("/static", StaticFiles(directory="web"), name="static")


@app.exception_handler(RequestValidationError)
async def validation_error_response(_: Request, exc: RequestValidationError):
    # Pydantic's default error payload may echo rejected input, including PII or secrets.
    safe_errors = [
        {"loc": list(error.get("loc", ())), "msg": error.get("msg", "Invalid input"),
         "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": safe_errors})


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
    # Never trust a client-supplied correlation ID: it can contain PII or log-control characters.
    request_id = str(uuid.uuid4())
    client = request.client.host if request.client else "unknown"
    try:
        allowed = limiter.check(rate_limit_bucket("request", client))
    except sqlite3.Error:
        logger.error("Rate limiter indisponível; requisição bloqueada.")
        return JSONResponse(status_code=503, content={"detail": "Controle de requisições temporariamente indisponível."},
                            headers={"Retry-After": "30", "X-Request-ID": request_id})
    if not allowed:
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
    try:
        user = get_current_user(request)
    except HTTPException:
        return {"authenticated": False, "user": None, "csrf_token": None}
    if user["id"] == 0 and user["username"] == "local-dev":
        return {"authenticated": True, "user": {"username": "local-dev", "role": "admin"}}
    return {
        "authenticated": True,
        "user": {"username": user["username"], "role": user["role"]},
        "csrf_token": request.session.get("csrf_token"),
    }


@app.post("/api/login")
def login(payload: LoginRequest, request: Request):
    origin = request.headers.get("origin")
    if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(status_code=403, detail="Origem da solicitação inválida.")
    client_ip = request.client.host if request.client else "unknown"
    attempt_key = rate_limit_bucket("login", client_ip, payload.username.casefold())
    try:
        allowed = login_limiter.check(attempt_key)
    except sqlite3.Error:
        logger.error("Rate limiter de login indisponível; autenticação bloqueada.")
        raise HTTPException(status_code=503, detail="Autenticação temporariamente indisponível.") from None
    if not allowed:
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 15 minutos.")
    user = database.get_user_by_username(payload.username)
    if not user and payload.username == settings.admin_username and settings.web_password and secrets.compare_digest(payload.password, settings.web_password):
        database.ensure_bootstrap_admin(settings.admin_username, hash_password(settings.web_password))
        user = database.get_user_by_username(settings.admin_username)
    if not user or not user["active"] or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")
    try:
        login_limiter.reset(attempt_key)
    except sqlite3.Error:
        logger.error("Não foi possível atualizar o rate limiter após login.")
        raise HTTPException(status_code=503, detail="Autenticação temporariamente indisponível.") from None
    request.session.clear()
    request.session["user"] = {"id": user["id"], "username": user["username"], "role": user["role"]}
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    return {"authenticated": True, "user": request.session["user"], "csrf_token": request.session["csrf_token"]}


@app.post("/api/logout")
def logout(
    request: Request,
    _: Annotated[dict, Depends(get_current_user)],
    __: None = Depends(verify_csrf),
):
    request.session.clear()
    return {"authenticated": False}


@app.get("/api/users", dependencies=[Depends(require_admin)])
def users():
    return database.list_users()


@app.patch("/api/users/{user_id}/active", dependencies=[Depends(require_admin), Depends(verify_csrf)])
def update_user_active(user_id: Annotated[int, Path(ge=1)], payload: UserActiveRequest,
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
def dashboard_stats(user: Annotated[dict, Depends(get_current_user)]):
    assigned_to = user["id"] if user["role"] == "agent" else None
    return database.ticket_stats(assigned_to)


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
def tickets(user: Annotated[dict, Depends(get_current_user)],
            limit: int = Query(default=50, ge=1, le=100),
            search: str | None = Query(default=None, min_length=1, max_length=100),
            status_filter: Annotated[Status | None, Query(alias="status")] = None,
            category: Category | None = None, priority: Priority | None = None):
    assigned_to = user["id"] if user["role"] == "agent" else None
    return database.list_tickets(limit, status_filter, category, priority, search, assigned_to)


@app.get("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(get_current_user)])
def ticket_detail(ticket_id: Annotated[int, Path(ge=1)], user: Annotated[dict, Depends(get_current_user)]):
    result = database.get_ticket(ticket_id)
    if result is None or (user["role"] == "agent" and result["assigned_to"] != user["id"]):
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/api/tickets/{ticket_id}/history", dependencies=[Depends(get_current_user)])
def ticket_history(ticket_id: Annotated[int, Path(ge=1)], user: Annotated[dict, Depends(get_current_user)]):
    ticket = database.get_ticket(ticket_id)
    if ticket is None or (user["role"] == "agent" and ticket["assigned_to"] != user["id"]):
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return database.get_ticket_history(ticket_id)


@app.patch("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(verify_csrf)])
def change_ticket_status(ticket_id: Annotated[int, Path(ge=1)], payload: TicketUpdate, user: Annotated[dict, Depends(get_current_user)]):
    ticket = database.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    if user["role"] == "agent" and ticket["assigned_to"] != user["id"]:
        raise HTTPException(status_code=403, detail="Agentes só podem atualizar chamados atribuídos a eles.")
    result = database.update_status(ticket_id, payload.status, actor=user)
    if result is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/api/users/assignable", dependencies=[Depends(require_admin)])
def assignable_users():
    return database.list_assignable_users()


@app.post("/api/tickets/{ticket_id}/assignment", dependencies=[Depends(require_admin), Depends(verify_csrf)])
def assign_ticket(ticket_id: Annotated[int, Path(ge=1)], payload: TicketAssignment, user: Annotated[dict, Depends(get_current_user)]):
    result = database.assign_ticket(ticket_id, payload.user_id, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Chamado ou usuário ativo não encontrado.")
    return result


@app.get("/api/tickets/{ticket_id}/comments", dependencies=[Depends(get_current_user)])
def ticket_comments(ticket_id: Annotated[int, Path(ge=1)], user: Annotated[dict, Depends(get_current_user)]):
    ticket = database.get_ticket(ticket_id)
    if ticket is None or (user["role"] == "agent" and ticket["assigned_to"] != user["id"]):
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return database.list_comments(ticket_id)


@app.post("/api/tickets/{ticket_id}/comments", status_code=201, dependencies=[Depends(verify_csrf)])
def add_ticket_comment(ticket_id: Annotated[int, Path(ge=1)], payload: TicketCommentCreate, user: Annotated[dict, Depends(get_current_user)]):
    ticket = database.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    if user["role"] == "agent" and ticket["assigned_to"] != user["id"]:
        raise HTTPException(status_code=403, detail="Agentes só podem comentar em chamados atribuídos a eles.")
    comment = database.add_comment(ticket_id, redact_sensitive_data(payload.body), user)
    if comment is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return comment


@app.get("/", include_in_schema=False)
def home():
    return FileResponse("web/index.html")
