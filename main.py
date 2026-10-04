import os
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Variables tomadas del entorno (que configuramos en el docker-compose)
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS", "tu_password")


class UserRegister(BaseModel):
  username: str
  password: str


@app.post("/api/auth/register")
def register_user(user: UserRegister):
  # PASO 1: Obtener el token de administrador de Keycloak
  token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
  payload = {
      "client_id": "admin-cli",
      "username": ADMIN_USER,
      "password": ADMIN_PASS,
      "grant_type": "password",
  }

  token_res = requests.post(token_url, data=payload)
  if token_res.status_code != 200:
    raise HTTPException(
        status_code=500, detail="No se pudo autenticar con Keycloak"
    )

  access_token = token_res.json().get("access_token")

  # PASO 2: Crear el usuario en la API de administración de Keycloak
  create_user_url = (
      f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
  )
  headers = {
      "Authorization": f"Bearer {access_token}",
      "Content-Type": "application/json",
  }
  user_data = {
      "username": user.username,
      "enabled": True,
      "credentials": [
          {"type": "password", "value": user.password, "temporary": False}
      ],
  }

  create_res = requests.post(
      create_user_url, json=user_data, headers=headers
  )

  if create_res.status_code == 201:
    return {"message": "Usuario creado exitosamente en Keycloak"}
  else:
    raise HTTPException(
        status_code=create_res.status_code,
        detail=f"Error al crear usuario en Keycloak: {create_res.text}",
    )