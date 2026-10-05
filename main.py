from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth

app = FastAPI(
    title="API Red Comunitaria",
    version="1.0.0",
)

# Configuración de CORS para permitir peticiones desde el frontend y navegadores
origins = [
    "http://192.168.0.107",
    "http://localhost",
    "http://localhost:80",
    "*",  # Permite cualquier origen (muy útil para desarrollo y pruebas en red local)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos (GET, POST, PUT, DELETE, OPTIONS)
    allow_headers=["*"],  # Permite todos los headers (Content-Type, Authorization, etc.)
)

# Incluimos las rutas de autenticación
app.include_router(auth.router)


@app.get("/")
def root():
    return {"message": "API de Usuarios corriendo correctamente"}