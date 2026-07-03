import os
from pydantic_settings import BaseSettings

# Get the absolute path of the backend directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Settings(BaseSettings):
    PROJECT_NAME: str = "Riskwise Vulnerability Multi-Scanner Platform"
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'vulnerabilities.db')}"
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")
    CHROMA_PATH: str = os.path.join(BASE_DIR, "data", "chroma_db")
    
    # ---------------------------------------------------------
    # GENERIC LLM CONFIGURATION
    # FIX: Changed model slug to "openrouter/free" to match 
    # $0.00 credit keys. This prevents billing/limit 403 errors.
    # ---------------------------------------------------------
    LLM_MODEL: str = "openrouter/free" 
    LLM_BASE_URL: str = "https://openrouter.ai/api/v1"

    # FIX: Pydantic V2 config to ignore leftover/system environment variables
    model_config = {
        "env_file": ".env",
        "extra": "ignore" 
    }

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)