"""Main FastAPI application for the PDF Library."""

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Query, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import os
import aiofiles
from datetime import datetime
import PyPDF2
import shutil
import logging
import tempfile
import httpx
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Open PDF Library")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dashboard API configuration
DASHBOARD_API = os.getenv("DASHBOARD_API", "http://3.235.132.127:8080")

# Background task to send flows to dashboard
async def log_flow_to_dashboard(flow_data: dict):
    """Send flow data to dashboard in background."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            # Login to get token
            try:
                login_resp = await client.post(
                    f"{DASHBOARD_API}/api/login",
                    json={"username": "admin", "password": "admin123"},
                    timeout=2.0
                )
                if login_resp.status_code == 200:
                    token = login_resp.json().get("access_token")
                    if token:
                        # Send flow with token
                        resp = await client.post(
                            f"{DASHBOARD_API}/api/flow",
                            json=flow_data,
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=2.0
                        )
                        logger.info(f"Flow logged to dashboard: {flow_data['flow_key']} (status: {resp.status_code})")
            except Exception as e:
                logger.debug(f"Failed to send flow to dashboard: {e}")
    except Exception as e:
        logger.error(f"Error in log_flow_to_dashboard: {e}")

# Middleware to send flows to dashboard
@app.middleware("http")
async def send_flow_to_dashboard(request: Request, call_next):
    """Send flow data to dashboard for monitoring."""
    # Get client IP - check forwarded headers first for spoofed IPs
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.headers.get("X-Real-IP", "") or
        (request.client.host if request.client else "unknown")
    )
    
    logger.info(f"[MIDDLEWARE] Request from {client_ip} to {request.url.path}")
    
    # Process request
    response = await call_next(request)
    
    # Log flow data to dashboard in background
    try:
        flow_key = hashlib.md5(f"{client_ip}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        flow_data = {
            "flow_key": flow_key,
            "src_ip": client_ip,
            "dst_ip": "127.0.0.1",  # This app's IP
            "src_port": 54321,  # Typical client port
            "dst_port": 9000,  # This app's port
            "protocol": 6,  # TCP
            "label": "Normal",  # Default to normal traffic
            "confidence": 0.95,
            "threat_level": "low",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        logger.info(f"[MIDDLEWARE] Created flow: {flow_key} from {client_ip}")
        
        # Schedule background task
        import asyncio
        asyncio.create_task(log_flow_to_dashboard(flow_data))
        logger.info(f"[MIDDLEWARE] Background task created for flow sending")
        
    except Exception as e:
        logger.error(f"[MIDDLEWARE ERROR] {e}", exc_info=True)
    
    return response
    
    return response

# Get the absolute path of the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure static files and templates (with error handling)
try:
    app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
except Exception as e:
    logger.warning(f"Could not mount static files: {e}")

try:
    templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
except Exception as e:
    logger.warning(f"Could not load templates: {e}")
    templates = None

# Create necessary directories
os.makedirs(os.path.join(BASE_DIR, "pdfs"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

logger.info("Application initialized with directories: pdfs, static, templates")

class PDFLibrary:
    def __init__(self):
        self.pdf_dir = os.path.join(BASE_DIR, "pdfs")
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        logger.info(f"PDFLibrary initialized with directory: {self.pdf_dir}")

    async def save_pdf(self, file: UploadFile) -> str:
        """Save uploaded PDF file and return filename."""
        if not file.filename.lower().endswith('.pdf'):
            raise HTTPException(status_code=400, detail="Only PDF files are allowed")

        # Create a temporary file for validation
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            content = await file.read()
            temp_file.write(content)
            temp_file.seek(0)

            # Check file size
            file_size = len(content)
            if file_size > self.max_file_size:
                raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")

            # Validate PDF
            try:
                PyPDF2.PdfReader(temp_file)
            except Exception as e:
                raise HTTPException(status_code=400, detail="Invalid file")

            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{file.filename}"
            file_path = os.path.join(self.pdf_dir, filename)

            # Save file
            temp_file.seek(0)
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(content)

            return filename
        finally:
            temp_file.close()
            os.unlink(temp_file.name)

        logger.info(f"File saved: {filename}")
        return filename

    def get_all_pdfs(self) -> List[dict]:
        """Get list of all PDF files with metadata."""
        pdfs = []
        for filename in os.listdir(self.pdf_dir):
            if filename.lower().endswith('.pdf'):
                file_path = os.path.join(self.pdf_dir, filename)
                stats = os.stat(file_path)
                
                # Get PDF metadata
                try:
                    with open(file_path, 'rb') as f:
                        pdf = PyPDF2.PdfReader(f)
                        num_pages = len(pdf.pages)
                except Exception:
                    num_pages = 0

                pdfs.append({
                    'filename': filename,
                    'size': stats.st_size,
                    'uploaded_at': datetime.fromtimestamp(stats.st_mtime),
                    'pages': num_pages
                })
        
        return sorted(pdfs, key=lambda x: x['uploaded_at'], reverse=True)

    def get_pdf_path(self, filename: str) -> str:
        """Get full path of PDF file."""
        file_path = os.path.join(self.pdf_dir, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="PDF file not found")
        return file_path

# Initialize PDF library
pdf_library = PDFLibrary()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render home page with list of PDFs."""
    try:
        pdfs = pdf_library.get_all_pdfs()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "pdfs": pdfs}
        )
    except Exception as e:
        logger.error(f"Error loading home page: {e}")
        return """
        <html><body style="font-family: Arial; padding: 20px;">
        <h1>Target Webapp</h1>
        <p>✅ Service is running on port 9000</p>
        <p><a href="/docs">API Docs</a></p>
        </body></html>
        """

@app.post("/upload")
async def upload_pdf(file: UploadFile = File(...)):
    """Upload a PDF file."""
    try:
        filename = await pdf_library.save_pdf(file)
        return {"filename": filename, "status": "success"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        raise HTTPException(status_code=500, detail="Error uploading file")

@app.get("/pdf/{filename}")
async def get_pdf(filename: str):
    """View a PDF file in browser."""
    file_path = pdf_library.get_pdf_path(filename)
    return FileResponse(
        file_path,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline"}
    )

@app.get("/search")
async def search_pdfs(
    query: str = Query(..., min_length=1),
    request: Request = None
):
    """Search PDFs by filename."""
    all_pdfs = pdf_library.get_all_pdfs()
    results = [
        pdf for pdf in all_pdfs
        if query.lower() in pdf['filename'].lower()
    ]
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "pdfs": results,
            "search_query": query
        }
    )

@app.delete("/pdf/{filename}")
async def delete_pdf(filename: str):
    """Delete a PDF file."""
    try:
        file_path = pdf_library.get_pdf_path(filename)
        os.remove(file_path)
        return {"status": "success", "message": f"Deleted {filename}"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting file")