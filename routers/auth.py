import base64
from datetime import datetime
import json
import os
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# 1. Definimos el router al inicio
router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

# 👇 CONFIGURACIÓN ACTUALIZADA AL NUEVO SERVIDOR Y REALM 👇
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://192.168.0.103:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "prueba")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "api-python")
CLIENT_SECRET = os.getenv(
    "KEYCLOAK_CLIENT_SECRET", "mKpUdtdqjXPxVxZtMdq53PGkTUHrjIlw"
)
# 👆 FIN DE LA CONFIGURACIÓN ACTUALIZADA 👆


class UserRegister(BaseModel):
  username: str
  password: str
  role: str


class UserLogin(BaseModel):
  username: str
  password: str


class UserUpdate(BaseModel):
  username: str
  new_password: str


class UserToggleStatus(BaseModel):
  username: str


# Función auxiliar para decodificar el payload de un JWT sin verificar firma
def parse_jwt_payload(token: str):
  try:
    payload_part = token.split(".")[1]
    payload_part += "=" * (-len(payload_part) % 4)
    decoded_bytes = base64.urlsafe_b64decode(payload_part)
    return json.loads(decoded_bytes.decode("utf-8"))
  except Exception:
    return {}


@router.post("/register")
def register_user(user: UserRegister):
    # 1. Obtenemos un token de administrador
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
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # 2. Creamos el usuario en Keycloak
    create_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
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

    if create_res.status_code != 201:
        raise HTTPException(
            status_code=create_res.status_code,
            detail=f"Error al crear usuario en Keycloak: {create_res.text}",
        )

    # 3. Obtenemos el ID del usuario recién creado
    search_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={user.username}&exact=true"
    search_res = requests.get(search_user_url, headers=headers)

    if search_res.status_code != 200 or not search_res.json():
        raise HTTPException(
            status_code=500,
            detail="Usuario creado pero no se pudo obtener su ID.",
        )

    user_id = search_res.json()[0]["id"]

    # 4. Obtenemos los detalles del rol (para tener su ID)
    role_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{user.role}"
    role_res = requests.get(role_url, headers=headers)

    if role_res.status_code != 200:
        raise HTTPException(
            status_code=404,
            detail=f"Rol '{user.role}' no encontrado en Keycloak.",
        )

    role_data = role_res.json()

    # 5. Asignamos el rol al usuario
    assign_url = (
        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm"
    )
    assign_res = requests.post(
        assign_url, json=[role_data], headers=headers
    )

    if assign_res.status_code != 204:
        raise HTTPException(
            status_code=assign_res.status_code,
            detail=f"Usuario creado pero falló al asignar el rol: {assign_res.text}",
        )

    # 6. Devolvemos la confirmación
    return {
        "message": "Usuario creado exitosamente en Keycloak",
        "username": user.username,
        "role": user.role,
    }


@router.post("/login")
def login_user(user: UserLogin):
    token_url = (
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    )
    
    # 1. Primero verificamos el estado del usuario en Keycloak antes de autenticar
    admin_token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    admin_payload = {"grant_type": "client_credentials"}
    admin_token_res = requests.post(
        admin_token_url, data=admin_payload, auth=(CLIENT_ID, CLIENT_SECRET)
    )
    
    if admin_token_res.status_code == 200:
        admin_access_token = admin_token_res.json().get("access_token")
        admin_headers = {"Authorization": f"Bearer {admin_access_token}"}
        
        search_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={user.username}&exact=true"
        search_res = requests.get(search_user_url, headers=admin_headers)
        
        if search_res.status_code == 200 and search_res.json():
            user_data = search_res.json()[0]
            # Si el usuario está deshabilitado (enabled = False), bloqueamos el login
            if not user_data.get("enabled", True):
                raise HTTPException(
                    status_code=403,
                    detail="El usuario se encuentra desactivado. Contacte al administrador.",
                )

    # 2. Si está activo, procedemos con el flujo normal de inicio de sesión
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
    access_token = tokens.get("access_token")

    jwt_payload = parse_jwt_payload(access_token)
    realm_roles = jwt_payload.get("realm_access", {}).get("roles", [])

    return {
        "message": "Inicio de sesión exitoso",
        "access_token": access_token,
        "refresh_token": tokens.get("refresh_token"),
        "expires_in": tokens.get("expires_in"),
        "roles": realm_roles,
    }


@router.put("/update-user")
def update_user(user: UserUpdate):
    """
    Actualiza la contraseña de un usuario existente en Keycloak.
    """
    # 1. Obtenemos un token de administrador
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
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # 2. Buscamos al usuario por su username
    search_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={user.username}&exact=true"
    search_res = requests.get(search_user_url, headers=headers)

    if search_res.status_code != 200 or not search_res.json():
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    user_id = search_res.json()[0]["id"]

    # 3. Actualizamos la contraseña
    reset_password_url = (
        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/reset-password"
    )
    credential_data = {
        "type": "password",
        "value": user.new_password,
        "temporary": False,
    }
    reset_res = requests.put(
        reset_password_url, json=credential_data, headers=headers
    )

    if reset_res.status_code != 204:
        raise HTTPException(
            status_code=reset_res.status_code,
            detail=f"Error al actualizar la contraseña: {reset_res.text}",
        )

    return {
        "message": "Contraseña actualizada exitosamente",
        "username": user.username,
    }


@router.get("/events")
def get_keycloak_events():
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
  headers = {"Authorization": f"Bearer {access_token}"}

  events_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/events"
  params = {"type": "LOGIN", "max": 20}

  events_res = requests.get(events_url, headers=headers, params=params)

  if events_res.status_code != 200:
    raise HTTPException(
        status_code=events_res.status_code,
        detail=f"Error al obtener los eventos de Keycloak: {events_res.text}",
    )

  raw_events = events_res.json()
  formatted_events = []

  for ev in raw_events:
    timestamp = ev.get("time")
    date_readable = (
        datetime.fromtimestamp(timestamp / 1000).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if timestamp
        else None
    )

    details = ev.get("details", {})
    username = details.get("username", "Desconocido")

    formatted_events.append({
        "user": username,
        "started": date_readable,
        "last_access": date_readable,
        "ip_address": ev.get("ipAddress"),
    })

  return {"total_events": len(formatted_events), "events": formatted_events}


@router.get("/users")
def get_non_admin_users():
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
    headers = {"Authorization": f"Bearer {access_token}"}

    users_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    users_res = requests.get(users_url, headers=headers)

    if users_res.status_code != 200:
        raise HTTPException(
            status_code=users_res.status_code,
            detail=f"Error al obtener los usuarios: {users_res.text}",
        )

    all_users = users_res.json()
    non_admin_users = []

    for user in all_users:
        user_id = user.get("id")
        username = user.get("username")

        roles_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm"
        roles_res = requests.get(roles_url, headers=headers)

        is_admin = False
        if roles_res.status_code == 200:
            realm_roles = roles_res.json()
            is_admin = any(
                role.get("name") in ["admin", "administrador_junta"] 
                for role in realm_roles
            )

        if not is_admin:
            is_enabled = user.get("enabled", True)
            status_str = "Activo" if is_enabled else "Inactivo"

            non_admin_users.append({
                "username": username,
                "status": status_str,
            })

    return {
        "total_users": len(non_admin_users),
        "users": non_admin_users
    }


@router.put("/toggle-status")
def toggle_user_status(user: UserToggleStatus):
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
  headers = {
      "Authorization": f"Bearer {access_token}",
      "Content-Type": "application/json",
  }

  search_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={user.username}&exact=true"
  search_res = requests.get(search_user_url, headers=headers)

  if search_res.status_code != 200 or not search_res.json():
    raise HTTPException(status_code=404, detail="Usuario no encontrado")

  user_data = search_res.json()[0]
  user_id = user_data["id"]
  current_status = user_data.get("enabled", True)

  new_status = not current_status

  update_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}"
  update_payload = {"enabled": new_status}

  update_res = requests.put(update_url, json=update_payload, headers=headers)

  if update_res.status_code == 204:
    status_text = "activado" if new_status else "desactivado"
    return {
        "message": f"Usuario {user.username} {status_text} exitosamente",
        "enabled": new_status,
    }
  else:
    raise HTTPException(
        status_code=update_res.status_code,
        detail=f"Error al cambiar el estado del usuario: {update_res.text}",
    )


@router.get("/roles", response_model=list[str])
def get_roles_with_access():
    """
    Retorna una lista con los nombres de los roles del Realm
    que tengan la palabra "Acceso" en su descripción.
    """
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
    headers = {"Authorization": f"Bearer {access_token}"}

    roles_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/roles"
    roles_res = requests.get(roles_url, headers=headers)

    if roles_res.status_code != 200:
        raise HTTPException(
            status_code=roles_res.status_code,
            detail=f"Error al obtener los roles: {roles_res.text}",
        )

    all_roles = roles_res.json()
    names = [
        role["name"]
        for role in all_roles
        if "Acceso" in role.get("description", "")
    ]

    return names