import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Habilitar CORS para permitir peticiones desde tu frontend estático
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de Keycloak utilizando variables de entorno de forma segura
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.getenv("KEYCLOAK_REALM", "master")
ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS", "admin")

class UserRegister(BaseModel):
    username: str
    password: str

def get_admin_token():
    """Obtiene un token de administrador desde Keycloak para poder gestionar usuarios"""
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": "admin-cli",
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "grant_type": "password"
    }
    response = requests.post(token_url, data=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error al autenticar con el Admin de Keycloak")
    return response.json().get("access_token")

@app.post("/api/auth/register")
def register_user(user: UserRegister):
    token = get_admin_token()
    
    create_user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    user_payload = {
        "username": user.username,
        "enabled": True,
        "credentials": [
            {
                "type": "password",
                "value": user.password,
                "temporary": False
            }
        ]
    }
    
    response = requests.post(create_user_url, headers=headers, json=user_payload)
    
    if response.status_code == 201:
        return {"message": "Usuario creado exitosamente en Keycloak"}
    elif response.status_code == 409:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)