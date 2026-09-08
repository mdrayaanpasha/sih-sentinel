"""Central config, env-driven. Import `settings` anywhere."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_flows_topic: str = "flows"
    kafka_alerts_topic: str = "alerts"
    kafka_consumer_group: str = "sentinel-workers"

    redis_url: str = "redis://localhost:6380/0"

    postgres_dsn: str = "postgresql://sentinel:sentinel@localhost:5434/sentinel"

    flow_serialization: str = "json"  # json | msgpack


settings = Settings()
