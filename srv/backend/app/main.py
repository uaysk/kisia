import os
import httpx
import docker
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Form
from sqlalchemy.orm import Session
from typing import List

from . import crud, models, auth, dependencies

from fastapi.middleware.cors import CORSMiddleware

# Create all tables in the database on startup
models.Base.metadata.create_all(bind=models.engine)

app = FastAPI()

# CORS Middleware Configuration
origins = ["*"] # Allow all origins for this PoC

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


UEM_URL = os.environ.get("UEM_URL")
NGINX_CONTAINER_NAME = os.environ.get("NGINX_CONTAINER_NAME")
NGINX_CONF_PATH = os.environ.get("NGINX_CONF_PATH")

# Helper function to reload Nginx
def reload_nginx():
    try:
        client = docker.from_env()
        nginx_container = client.containers.get(NGINX_CONTAINER_NAME)
        nginx_container.exec_run("nginx -s reload")
        return {"status": "success", "message": "Nginx reloaded"}
    except Exception as e:
        print(f"Error reloading Nginx: {e}")
        # In a real app, you'd have more robust error handling
        raise HTTPException(status_code=500, detail=f"Failed to reload Nginx: {str(e)}")

# Helper function to generate Nginx config
def generate_nginx_config(service: models.ServiceInDB):
    return f"""
location {service.access_path} {{
    # Static auth_request URI using path-style endpoint
    auth_request /api/check_auth{service.access_path};

    # If auth fails or backend/UEM errors occur, return 403 (not 500)
    error_page 401 403 404 500 502 503 = @error_response;

    proxy_pass {service.upstream_url};
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}}
"""

@app.get("/")
def read_root():
    return {"message": "ZTNA PoC Backend is running"}

# --- Authentication Endpoints ---
@app.post("/login")
async def login_for_session_cookie(response: Response, form_data: Request, db: Session = Depends(dependencies.get_db)):
    form = await form_data.form()
    username = form.get("username")
    password = form.get("password")
    user = crud.get_user_by_username(db, username=username)
    if not user or not auth.verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    auth.create_session_cookie(response, username, key="session_id")
    return {"message": "Login successful"}

@app.post("/admin/login")
async def admin_login_for_session_cookie(response: Response, form_data: Request, db: Session = Depends(dependencies.get_db)):
    form = await form_data.form()
    username = form.get("username")
    password = form.get("password")
    admin = crud.get_admin_by_username(db, username=username)
    if not admin or not auth.verify_password(password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect admin username or password",
        )
    auth.create_session_cookie(response, username, key="admin_session_id")
    return {"message": "Admin login successful"}

@app.post("/logout")
def logout(response: Response):
    auth.delete_session_cookie(response, key="session_id")
    auth.delete_session_cookie(response, key="admin_session_id")
    return {"message": "Logout successful"}

# --- ZTNA Core Auth Check Endpoint ---
@app.get("/api/check_auth")
async def check_auth(request: Request, uri: str, db: Session = Depends(dependencies.get_db)):
    username = request.cookies.get("session_id")
    print(f"DEBUG: check_auth received for URI: '{uri}'")

    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session cookie")

    # 1. Get required score for the requested service
    service = crud.get_service_by_access_path(db, access_path=uri)
    if not service:
        # Return 403 to avoid surfacing 404 as 500 via auth_request
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Service for path {uri} not found")
    
    required_score = service.required_score

    # 2. Get user's current score from UEM
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{UEM_URL}/score/{username}")
            res.raise_for_status()
            user_score = res.json().get("score", 0)
    except httpx.RequestError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"UEM service unavailable: {e}")

    # 3. Compare scores and authorize
    if user_score >= required_score:
        return Response(status_code=status.HTTP_200_OK)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient security score")

# Path-style variant to avoid query-string encoding issues
@app.get("/api/check_auth/{full_path:path}")
async def check_auth_by_path(request: Request, full_path: str, db: Session = Depends(dependencies.get_db)):
    uri = "/" + full_path.lstrip("/")
    username = request.cookies.get("session_id")
    print(f"DEBUG: check_auth (by_path) received for URI: '{uri}'")

    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session cookie")

    service = crud.get_service_by_access_path(db, access_path=uri)
    if not service:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Service for path {uri} not found")

    required_score = service.required_score

    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{UEM_URL}/score/{username}")
            res.raise_for_status()
            user_score = res.json().get("score", 0)
    except httpx.RequestError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"UEM service unavailable: {e}")

    if user_score >= required_score:
        return Response(status_code=status.HTTP_200_OK)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient security score")

# --- Admin CRUD APIs ---

# Users
@app.get("/admin/users", response_model=List[models.UserInDB])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    return crud.get_users(db, skip=skip, limit=limit)

@app.post("/admin/users", response_model=models.UserInDB)
def create_user(user: models.UserCreate, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

@app.delete("/admin/users/{user_id}", response_model=models.UserInDB)
def delete_user(user_id: int, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_user = crud.delete_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# Admins
@app.get("/admin/admins", response_model=List[models.AdminInDB])
def read_admins(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    return crud.get_admins(db, skip=skip, limit=limit)

@app.post("/admin/admins", response_model=models.AdminInDB)
def create_admin(admin_user: models.AdminCreate, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_admin = crud.get_admin_by_username(db, username=admin_user.username)
    if db_admin:
        raise HTTPException(status_code=400, detail="Admin username already registered")
    return crud.create_admin(db=db, admin=admin_user)

@app.delete("/admin/admins/{admin_id}", response_model=models.AdminInDB)
def delete_admin(admin_id: int, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_admin = crud.delete_admin(db, admin_id=admin_id)
    if db_admin is None:
        raise HTTPException(status_code=404, detail="Admin not found")
    return db_admin

# Services
@app.get("/api/services", response_model=List[models.ServiceInDB])
def read_services_public(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db)):
    return crud.get_services(db, skip=skip, limit=limit)

@app.get("/admin/services", response_model=List[models.ServiceInDB])
def read_services_admin(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    return crud.get_services(db, skip=skip, limit=limit)

@app.post("/admin/services", response_model=models.ServiceInDB)
def create_service(service: models.ServiceCreate, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_service = crud.create_service(db=db, service=service)
    config = generate_nginx_config(db_service)
    config_path = os.path.join(NGINX_CONF_PATH, f"{db_service.name}.conf")
    with open(config_path, "w") as f:
        f.write(config)
    reload_nginx()
    return db_service

@app.delete("/admin/services/{service_id}", response_model=models.ServiceInDB)
def delete_service(service_id: int, db: Session = Depends(dependencies.get_db), admin: models.AdminInDB = Depends(dependencies.get_current_admin)):
    db_service = crud.get_service(db, service_id=service_id)
    if db_service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    
    config_path = os.path.join(NGINX_CONF_PATH, f"{db_service.name}.conf")
    if os.path.exists(config_path):
        os.remove(config_path)
    
    deleted_service = crud.delete_service(db, service_id=service_id)
    reload_nginx()
    return deleted_service
