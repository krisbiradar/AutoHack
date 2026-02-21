from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import os

from .config import load_config
from .storage import StorageEngine

app = FastAPI(title="Security Auditor Dashboard")

# Templates directory setup
# Assuming the script runs from src or project root
base_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(base_dir, "templates")
os.makedirs(templates_dir, exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)

@app.on_event("startup")
async def startup_event():
    # Load config and initialize storage engine
    # In a real app we might inject this dependency better, but this suffices for a minimal dashboard
    global storage
    # Try to load from default location assumes running from project root
    config_path = "config.yaml" if os.path.exists("config.yaml") else "../config.yaml"
    try:
        config = load_config(config_path)
        storage = StorageEngine(config.database_path)
    except Exception as e:
        print(f"Warning: Could not load config for dashboard: {e}")
        storage = None

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    if not storage:
        return HTMLResponse("<h1>Configuration Error</h1><p>Could not initialize storage engine.</p>")
        
    vulnerabilities = await storage.get_recent_vulnerabilities(limit=100)
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "vulnerabilities": vulnerabilities})

def run_dashboard(host: str = "127.0.0.1", port: int = 8000):
    """Run the FastAPI web application using uvicorn."""
    uvicorn.run("src.api:app", host=host, port=port, reload=False)
