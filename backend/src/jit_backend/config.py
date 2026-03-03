from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Settings:
    jwt_secret: str
    jwt_algo: str
    jwt_expire_minutes: int
    db_path: Path
    admin_secret_name: str
    admin_secret_namespace: str


def load_settings() -> Settings:
    return Settings(
        jwt_secret=os.getenv("JIT_JWT_SECRET", "change-me"),
        jwt_algo=os.getenv("JIT_JWT_ALGO", "HS256"),
        jwt_expire_minutes=int(os.getenv("JIT_JWT_EXPIRE_MIN", "120")),
        db_path=Path(os.getenv("JIT_DB_PATH", "/data/jit_audit.db")),
        admin_secret_name=os.getenv("JIT_ADMIN_SECRET_NAME", "jit-admin-auth"),
        admin_secret_namespace=os.getenv("JIT_ADMIN_SECRET_NAMESPACE", "default"),
    )
