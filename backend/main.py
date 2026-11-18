from fastapi import FastAPI
from database import init_db
from routers import auth, files
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()

app = FastAPI(title="TrustShare API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize PostgreSQL Tables
@app.on_event("startup")
def startup_event():
    init_db()

# Include Auth Router
app.include_router(auth.router)
app.include_router(files.router)

@app.get("/")
def root():
    return {"message": "Welcome to TrustShare Secure File-Sharing API"}