import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

# Path dasar direktori aplikasi dan file .env
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

app = FastAPI(
    title="SOC Analysis Console",
    description="Aplikasi web internal stateless untuk analisis triage log dan deteksi IoC Security Operations Center",
    version="1.0.0"
)

# Konfigurasi CORS (akses internal fleksibel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mounting folder Static Files dan Templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Registrasi Router API
app.include_router(api_router)

@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def render_dashboard(request: Request):
    """Render halaman utama dashboard SOC Dark Mode."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": "SOC Analyst Workbench",
            "environment": "INTERNAL / STATELESS"
        }
    )

if __name__ == "__main__":
    import uvicorn
    # Menjalankan server development secara langsung
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
