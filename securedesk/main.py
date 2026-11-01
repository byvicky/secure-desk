import logging, uuid
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse\nfrom fastapi.staticfiles import StaticFiles
from securedesk import database
from securedesk.config import settings
from securedesk.schemas import TicketCreate,TicketOut,TicketUpdate
from securedesk.security import RateLimiter,redact_sensitive_data,verify_api_key
from securedesk.triage import analyze
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger("securedesk")
limiter=RateLimiter(settings.rate_limit)
@asynccontextmanager
async def lifespan(_:FastAPI):
    database.initialize()
    yield
app=FastAPI(title="SecureDesk API",description="API de triagem segura de solicitações de suporte.",version="0.1.0",docs_url=None if settings.production else "/docs",redoc_url=None if settings.production else "/redoc",lifespan=lifespan)
app.mount("/static", StaticFiles(directory="web"), name="static")\nif settings.cors_origins:
    app.add_middleware(CORSMiddleware,allow_origins=list(settings.cors_origins),allow_credentials=False,allow_methods=["GET","POST","PATCH"],allow_headers=["Authorization","Content-Type","X-Request-ID"])
@app.middleware("http")
async def security_headers(request:Request,call_next):
    request_id=request.headers.get("X-Request-ID",str(uuid.uuid4()))[:64]
    client=request.client.host if request.client else "unknown"
    if not limiter.check(client):
        return JSONResponse(status_code=429,content={"detail":"Limite de requisições excedido."},headers={"Retry-After":"60","X-Request-ID":request_id})
    try: response=await call_next(request)
    except Exception:
        logger.exception("Erro interno request_id=%s",request_id)
        response=JSONResponse(status_code=500,content={"detail":"Erro interno do servidor."})
    response.headers.update({"X-Request-ID":request_id,"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Cache-Control":"no-store","Content-Security-Policy":"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"})
    return response
@app.get("/api/health")
def health():return {"status":"ok","service":"SecureDesk"}
@app.post("/api/tickets",response_model=TicketOut,status_code=status.HTTP_201_CREATED,dependencies=[Depends(verify_api_key)])
def submit_ticket(payload:TicketCreate):
    title=redact_sensitive_data(payload.title); description=redact_sensitive_data(payload.description); requester=redact_sensitive_data(payload.requester)
    category,priority=analyze(title,description,payload.category)
    return database.create_ticket({"requester":requester,"title":title,"description":description,"category":category,"priority":priority})
@app.get("/api/tickets",response_model=list[TicketOut],dependencies=[Depends(verify_api_key)])
def tickets(limit:int=Query(default=50,ge=1,le=100)):return database.list_tickets(limit)
@app.get("/api/tickets/{ticket_id}",response_model=TicketOut,dependencies=[Depends(verify_api_key)])
def ticket_detail(ticket_id:int):
    result=database.get_ticket(ticket_id)
    if result is None:raise HTTPException(status_code=404,detail="Solicitação não encontrada.")
    return result
@app.patch("/api/tickets/{ticket_id}",response_model=TicketOut,dependencies=[Depends(verify_api_key)])
def change_ticket_status(ticket_id:int,payload:TicketUpdate):
    result=database.update_status(ticket_id,payload.status)
    if result is None:raise HTTPException(status_code=404,detail="Solicitação não encontrada.")
    return result
@app.get("/",include_in_schema=False)
def home():return FileResponse("web/index.html")
