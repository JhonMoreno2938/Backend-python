import os
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://192.168.0.107:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "backend-client")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")


class UserRegister(BaseModel):
  username: str
  password: str


@app.post("/api/auth/register")
def register_user(user: UserRegister):
  token_url = (
      f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
  )

  # Para clientes confidenciales, Keycloak prefiere o requiere HTTP Basic Auth
  payload = {
      "grant_type": "client_credentials",
  }

  token_res = requests.post(
      token_url, data=payload, auth=(CLIENT_ID, CLIENT_SECRET)
  )

  if token_res.status_code != 200:
    print(f"Error de Keycloak -> Status: {token_res.status_code}")
    print(f"Respuesta de Keycloak: {token_res.text}")
    raise HTTPException(
        status_code=500, detail=f"Error Keycloak Auth: {token_res.text}"
    )

  access_token = token_res.json().get("access_token")

  # PASO 2: Crear el usuario en la API de administración de Keycloak
  create_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
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
    print(f"Error al crear usuario -> Status: {create_res.status_code}")
    print(f"Detalle: {create_res.text}")
    raise HTTPException(
        status_code=create_res.status_code,
        detail=f"Error al crear usuario en Keycloak: {create_res.text}",
    )