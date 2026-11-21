import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MongoDB URI is missing. Set MONGODB_URI in the backend environment.")

# MongoClient connects lazily. The API health route can start without blocking on Atlas.
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=10000)
db = client[os.getenv("DB_NAME", "entry_shield")]
visits_collection = db.gate_passes
receipts_collection = db.receipts
users_collection = db.users
roles_collection = db.roles
students_collection = db.students

def ensure_indexes():
    """Preserve the app's intended non-unique gate-pass behavior and user lookup index."""
    try:
        index_info = visits_collection.index_information().get("studentId_1")
        if index_info and index_info.get("unique"):
            visits_collection.drop_index("studentId_1")
            print("Dropped the legacy unique studentId index on gate_passes.")
    except Exception as exc:
        # Missing indexes are normal on a new database; surface other errors in logs.
        if "index not found" not in str(exc).lower() and "indexnotfound" not in str(exc).lower():
            print(f"Index check warning: {exc}")

    users_collection.create_index("clerk_id", unique=True)

    try:
        receipts_collection.drop_index("visitId_1")
    except Exception as exc:
        if "index not found" not in str(exc).lower() and "indexnotfound" not in str(exc).lower():
            print(f"Receipt index check warning: {exc}")
