import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pymongo import MongoClient
import redis

load_dotenv()

# PostgreSQL Database Configuration
engine = create_engine(os.getenv("DATABASE_URL"))

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)
Base = declarative_base()

# MongoDB (Audit logs, activity records)[cite: 2]
mongo_client = MongoClient(os.getenv("MONGO_URL"))
mongo_db = mongo_client["trustshare_logs"]
audit_collection = mongo_db["audit_logs"]

# Redis (Caching, sessions, tokens)
redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL"),
    decode_responses=True
)

# Function to create PostgreSQL tables
def init_db():
    Base.metadata.create_all(bind=engine)
