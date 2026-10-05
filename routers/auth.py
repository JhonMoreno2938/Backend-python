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


class UserUpdatePassword(BaseModel):
  username: str
  new_password: str


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


@router.put("/update-password")
def update_password(user: UserUpdatePassword):
  token_url = (
      f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
  )

  # 1. Obtenemos el token de administrador
  payload = {"grant_type": "client_credentials"}
  token_res = requests.post(
      token_url, data=payload, auth=(CLIENT_ID, CLIENT_SECRET)
  )

  if token_res.status_code != 200:
    raise HTTPException(
        status_code=500, detail=f"Error Keycloak Auth: {token_res.text}"
    )

  access_token = token_res.json().get("access_token")

  # 2. Primero necesitamos buscar el ID del usuario a partir de su username
  search_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={user.username}&exact=true"
  headers = {"Authorization": f"Bearer {access_token}"}

  search_res = requests.get(search_user_url, headers=headers)

  if search_res.status_code != 200 or not search_res.json():
    raise HTTPException(status_code=404, detail="Usuario no encontrado")

  user_id = search_res.json()[0]["id"]

  # 3. Actualizamos la contraseña del usuario usando la API de Admin
  reset_password_url = (
      f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/reset-password"
  )
  reset_headers = {
      "Authorization": f"Bearer {access_token}",
      "Content-Type": "application/json",
  }

  # Estructura para la nueva credencial
  credential_data = {
      "type": "password",
      "value": user.new_password,
      "temporary": False,  # Si está en False, la contraseña queda fija de inmediato sin pedir cambio al iniciar sesión
  }

  reset_res = requests.put(
      reset_password_url, json=credential_data, headers=reset_headers
  )

  if reset_res.status_code == 204:
    return {"message": "Contraseña actualizada exitosamente en Keycloak"}
  else:
    raise HTTPException(
        status_code=reset_res.status_code,
        detail=f"Error al actualizar la contraseña: {reset_res.text}",
    )