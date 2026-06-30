from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import socket
import nmap
import uuid

app = FastAPI()

# Enable CORS for frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_JOBS = {}

def perform_nmap_scan(task_id: str, target_ip: str):
    # Step 1: Initializing the scan task
    SCAN_JOBS[task_id] = {"state": "PROGRESS", "percent": 20, "status": "Initializing Nmap system..."}
    
    try:
        nm = nmap.PortScanner()
        
        # Step 2: Actively scanning common network ports
        SCAN_JOBS[task_id] = {"state": "PROGRESS", "percent": 50, "status": "Scanning common ports (21-8080)..."}
        nm.scan(target_ip, arguments='-p 21,22,23,25,53,80,443,8080 -sV --version-light')
        
        # Step 3: Analyzing discovered port banners and services
        SCAN_JOBS[task_id] = {"state": "PROGRESS", "percent": 80, "status": "Analyzing open port banners..."}
        
        scan_results = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                lport = nm[target_ip][proto].keys()
                for port in lport:
                    state = nm[target_ip][proto][port]['state']
                    service = nm[target_ip][proto][port]['name']
                    version = nm[target_ip][proto][port]['version']
                    
                    if state == 'open':
                        scan_results.append({
                            "port": port,
                            "service": service,
                            "version": version if version else "Unknown"
                        })
                        
        # Step 4: Scan successfully finalized
        SCAN_JOBS[task_id] = {
            "state": "SUCCESS",
            "percent": 100,
            "status": "Scan completed successfully!",
            "result": {"status": "Completed", "open_ports": scan_results}
        }
    except Exception as e:
        SCAN_JOBS[task_id] = {
            "state": "SUCCESS",
            "percent": 100,
            "result": {"error": f"Scan failed: {str(e)}"}
        }

@app.post("/api/start-scan")
async def start_scan(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    target = data.get("target")
    
    # Block localhost scanning for safety
    if target in ["127.0.0.1", "0.0.0.0", "localhost"]:
        return JSONResponse(status_code=400, content={"error": "Scanning localhost is not allowed!"})
        
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return JSONResponse(status_code=400, content={"error": "Invalid domain name or IP address!"})

    task_id = str(uuid.uuid4())
    SCAN_JOBS[task_id] = {"state": "PROGRESS", "percent": 10, "status": "Task added to queue..."}
    background_tasks.add_task(perform_nmap_scan, task_id, target_ip)
    return {"task_id": task_id, "target_ip": target_ip}

@app.get("/api/scan-status/{task_id}")
def get_status(task_id: str):
    return SCAN_JOBS.get(task_id, {"state": "PENDING", "percent": 0, "status": "Waiting..."})