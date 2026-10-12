from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth

app = FastAPI(
    title="API Red Comunitaria",
    version="1.0.0",
)

# Configuración de CORS
# Solo el frontend hace peticiones a esta API
origins = [
    "http://192.168.0.101",          # Frontend
    "http://192.168.0.101:8081",       # Frontend en puerto 80
    "http://192.168.0.101:8000",     # La propia API (para Swagger /docs)
    "http://localhost",              # Para desarrollo local
    "http://localhost:80",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluimos las rutas de autenticación
app.include_router(auth.router)


@app.get("/")
def root():
    return {"message": "API de Usuarios corriendo correctamente"}