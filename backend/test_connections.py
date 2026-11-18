from database import engine, mongo_client, redis_client
from sqlalchemy import text

# Test PostgreSQL Connection
with engine.connect() as connection:
    connection.execute(text("SELECT 1"))
    print("PostgreSQL Connected Successfully!")

# Test MongoDB
mongo_client.admin.command("ping")
print("MongoDB Connected Successfully!")

# 3. Test Redis
redis_client.ping()
print("Redis Connected Successfully!")