import os
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://192.168.0.107:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "backend-client")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")


class UserRegister(BaseModel):
  username: str
  password: str


class UserLogin(BaseModel):
  username: str
  password: str


@router.post("/register")
def register_user(user: UserRegister):
  token_url = (
      f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
  )
  payload = {"grant_type": "client_credentials"}

  token_res = requests.post(
      token_url, data=payload, auth=(CLIENT_ID, CLIENT_SECRET)
  )
  if token_res.status_code != 200:
    raise HTTPException(
        status_code=500, detail=f"Error Keycloak Auth: {token_res.text}"
    )

  access_token = token_res.json().get("access_token")
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
    raise HTTPException(
        status_code=create_res.status_code,
        detail=f"Error al crear usuario en Keycloak: {create_res.text}",
    )


@router.post("/login")
def login_user(user: UserLogin):
  token_url = (
      f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
  )
  payload = {
      "grant_type": "password",
      "client_id": CLIENT_ID,
      "client_secret": CLIENT_SECRET,
      "username": user.username,
      "password": user.password,
  }
  headers = {"Content-Type": "application/x-www-form-urlencoded"}

  token_res = requests.post(token_url, data=payload, headers=headers)
  if token_res.status_code != 200:
    raise HTTPException(
        status_code=401,
        detail="Credenciales inválidas o error en el inicio de sesión",
    )

  tokens = token_res.json()
  return {
      "message": "Inicio de sesión exitoso",
      "access_token": tokens.get("access_token"),
      "refresh_token": tokens.get("refresh_token"),
      "expires_in": tokens.get("expires_in"),
  }