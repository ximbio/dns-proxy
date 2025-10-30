from ipaddress import ip_address
import json
import os

from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from loguru import logger

class Rules(BaseModel):
    blocklist: set[str]
    redirect_map: dict[str, str]

    
class Config(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    USE_DOT: bool = False
    USE_DOH: bool = True

    DOH_PORT: int = 8000
    DOH_HOST: str = "127.0.0.1"

    DOT_PORT: int
    DOT_HOST: str

    DOT_CERT_FILE: str
    DOT_KEY_FILE: str

    LOG_LEVEL: str = "INFO"
    UPSTREAM_DNS: list[str] = ["1.1.1.1"]

settings = Config()

def load_rules():
    path = "rules.json"
    
    if not os.path.exists(path):
        default_data = {
            "blocklist": [],
            "blocklist_file": "",
            "redirect_map": {}
        }
        with open(path, "w", encoding="utf8") as file:
            json.dump(default_data, file, ensure_ascii=False, indent=4)
        
        logger.warning(f"{path} not found. {path} has been created automatically.")

    with open("rules.json", "r", encoding="utf8") as file:
        data = json.load(file)
    
    blocklist = set(data["blocklist"])

    if data["blocklist_file"]:
        with open(data["blocklist_file"], "r", encoding="utf8") as file:
            blocklist = blocklist.union(set(json.load(file)))

    rules = Rules(
        redirect_map=data["redirect_map"],
        blocklist=blocklist
    )
    
    logger.info(f"Rules Loaded. Blocked: {len(blocklist)} domains. Redirected: {len(rules.redirect_map)} domains")
    return rules
