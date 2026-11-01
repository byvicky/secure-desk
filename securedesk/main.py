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
from securedesk.schemas import Category, Priority, Status, TicketCreate, TicketOut, TicketUpdate
from securedesk.security import RateLimiter, redact_sensitive_data, verify_api_key
from securedesk.triage import analyze

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securedesk")
limiter = RateLimiter(settings.rate_limit)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    yield


app = FastAPI(
    title="SecureDesk API",
    description="API de triagem segura de solicitações de suporte.",
    version="0.1.0",
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
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:64]
    client = request.client.host if request.client else "unknown"
    if not limiter.check(client):
        return JSONResponse(
            status_code=429,
            content={"detail": "Limite de requisições excedido."},
            headers={"Retry-After": "60", "X-Request-ID": request_id},
        )
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
    return {"authenticated": bool(request.session.get("authenticated"))}


@app.post("/api/login")
def login(payload: LoginRequest, request: Request):
    if not settings.web_password or not settings.session_secret:
        raise HTTPException(
            status_code=503,
            detail="Login web não configurado no servidor.",
        )
    origin = request.headers.get("origin")
    if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(status_code=403, detail="Origem da solicitação inválida.")
    if not secrets.compare_digest(payload.password, settings.web_password):
        raise HTTPException(status_code=401, detail="Senha incorreta.")
    request.session.clear()
    request.session["authenticated"] = True
    return {"authenticated": True}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"authenticated": False}


@app.post(
    "/api/tickets",
    response_model=TicketOut,
    dependencies=[Depends(verify_api_key)],
)
def submit_ticket(payload: TicketCreate):
    title = redact_sensitive_data(payload.title)
    description = redact_sensitive_data(payload.description)
    requester = redact_sensitive_data(payload.requester)
    category, priority = analyze(title, description, payload.category)
    return database.create_ticket({
        "requester": requester,
        "title": title,
        "description": description,
        "category": category,
        "priority": priority,
    })


@app.get("/api/tickets", response_model=list[TicketOut], dependencies=[Depends(verify_api_key)])
def tickets(
    limit: int = Query(default=50, ge=1, le=100),
    status_filter: Annotated[Status | None, Query(alias="status")] = None,
    category: Category | None = None,
    priority: Priority | None = None,
):
    return database.list_tickets(limit, status_filter, category, priority)


@app.get("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(verify_api_key)])
def ticket_detail(ticket_id: int):
    result = database.get_ticket(ticket_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/api/tickets/{ticket_id}/history", dependencies=[Depends(verify_api_key)])
def ticket_history(ticket_id: int):
    if database.get_ticket(ticket_id) is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return database.get_ticket_history(ticket_id)


@app.patch("/api/tickets/{ticket_id}", response_model=TicketOut, dependencies=[Depends(verify_api_key)])
def change_ticket_status(ticket_id: int, payload: TicketUpdate):
    result = database.update_status(ticket_id, payload.status)
    if result is None:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return result


@app.get("/", include_in_schema=False)
def home():
    return FileResponse("web/index.html")
