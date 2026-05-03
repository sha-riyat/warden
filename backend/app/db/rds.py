"""
Connexion et modèles SQLAlchemy pour RDS PostgreSQL.
"""
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    JSON, String, Text, create_engine, text
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
import uuid

Base = declarative_base()


class Owner(Base):
    """Personne physique ou morale responsable d'un ou plusieurs agents."""
    __tablename__ = "owners"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    did = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False)  # Chiffré, jamais en clair
    api_key = Column(String, unique=True, nullable=False, index=True)
    kyc_status = Column(String, default="pending")  # pending | verified | rejected
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Agent(Base):
    """Agent IA enregistré sous un owner."""
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    did = Column(String, unique=True, nullable=False, index=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("owners.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    erc8004_id = Column(String, nullable=True)  # ID ERC-8004 optionnel
    status = Column(String, default="active")  # active | revoked
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Credential(Base):
    """Délégation signée émise par un owner pour un agent."""
    __tablename__ = "credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("owners.id"), nullable=False)
    token = Column(Text, nullable=False)       # JWT signé complet
    permissions = Column(JSON, nullable=False)  # ["read:invoices", ...]
    issued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


def get_engine():
    """Crée le moteur SQLAlchemy depuis DATABASE_URL."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable is required")
    return create_engine(database_url, pool_pre_ping=True, pool_recycle=300)


def get_session() -> Session:
    """Crée une session de base de données."""
    engine = get_engine()
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def create_tables():
    """Crée toutes les tables si elles n'existent pas."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    print("✓ Tables créées : owners, agents, credentials")


def generate_api_key() -> str:
    """Génère une API key au format wdn_live_xxx."""
    import secrets
    token = secrets.token_urlsafe(32)
    return f"wdn_live_{token}"