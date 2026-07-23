from motor.motor_asyncio import AsyncIOMotorClient
from backend.app.config.settings import settings
from backend.app.utils.helpers import get_logger

logger = get_logger("database")

class Database:
    client: AsyncIOMotorClient = None
    db = None

db_instance = Database()

async def connect_to_mongo():
    """Establishes connection to MongoDB."""
    logger.info(f"Connecting to MongoDB at {settings.MONGO_URI}...")
    try:
        db_instance.client = AsyncIOMotorClient(settings.MONGO_URI)
        db_instance.db = db_instance.client[settings.MONGO_DB_NAME]
        # Ping database to verify connection
        await db_instance.client.admin.command('ping')
        logger.info("Successfully connected to MongoDB.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        db_instance.client = None
        db_instance.db = None
        # In a real environment, we'd raise or retry. For robustness, we will allow it to start and log failures.
        raise e

async def close_mongo_connection():
    """Closes connection to MongoDB."""
    if db_instance.client:
        db_instance.client.close()
        logger.info("MongoDB connection closed.")

def get_database():
    """Returns database instance."""
    return db_instance.db
