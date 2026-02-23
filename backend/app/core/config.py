import os
from pydantic_settings import BaseSettings

# Get the absolute path of the backend directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Settings(BaseSettings):
    PROJECT_NAME: str = "Al-Assisted Multi-Scanner Vulnerability Assessment Platform"
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'vulnerabilities.db')}"
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")
    CHROMA_PATH: str = os.path.join(BASE_DIR, "data", "chroma_db")
    LLM_KEY_PATH: str = os.path.join(BASE_DIR, "data", "llm_key.txt")
    
    LLM_MODEL: str = "openrouter/free"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    class Config:
        env_file = ".env"

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)