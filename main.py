from fastapi import FastAPI
from routers import auth

app = FastAPI(
    title="API Red Comunitaria",
    version="1.0.0",
)

# Incluimos las rutas de autenticación
app.include_router(auth.router)


@app.get("/")
def root():
  return {"message": "API de Usuarios corriendo correctamente"}