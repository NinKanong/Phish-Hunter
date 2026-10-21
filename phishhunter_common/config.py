from pydantic_settings import BaseSettings, SettingsConfigDict

class CommonSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "PhishGuard"
    max_upload_mb: int = 25
