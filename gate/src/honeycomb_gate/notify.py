"""Incident notifications: email (SMTP) and a generic webhook (F11, ADR-0007).

Credentials come from the environment (``.env``), never from the config file or the repo.
Sending happens off the hot path and a failure never stops the gate: it is logged, and the
incident record still holds the full message.
"""

import asyncio
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from honeycomb_gate.incidents import Incident, render_text


class NotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: bool = False
    webhook_url: str | None = None  # or set ALERT_WEBHOOK_URL in the environment
    subject_prefix: str = "[Honeycomb]"
    dedupe_window_s: int = Field(default=300, ge=0)
    # A high or critical incident nobody has acknowledged is sent again after this many seconds,
    # and then again every time as long as it stays open, up to `escalate_max` extra messages.
    escalate_after_s: int = Field(default=600, ge=0)  # 0 turns escalation off
    escalate_max: int = Field(default=3, ge=1, le=20)
    timeout_s: float = Field(default=10.0, gt=0, le=60)


def load_dotenv(path: Path = Path(".env")) -> None:
    """Load KEY=VALUE lines into the environment without overriding anything already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)


@dataclass
class EmailSettings:
    host: str
    port: int
    user: str
    password: str
    security: str  # starttls | ssl | none
    sender: str
    recipients: list[str]


def email_settings() -> EmailSettings | None:
    env = os.environ
    host, user, password = env.get("SMTP_HOST"), env.get("SMTP_USER"), env.get("SMTP_PASSWORD")
    recipients = [r.strip() for r in env.get("ALERT_EMAIL_TO", "").split(",") if r.strip()]
    if not (host and recipients):
        return None
    return EmailSettings(
        host=host,
        port=int(env.get("SMTP_PORT", "587")),
        user=user or "",
        password=password or "",
        security=env.get("SMTP_SECURITY", "starttls").lower(),
        sender=env.get("ALERT_EMAIL_FROM") or user or "honeycomb@localhost",
        recipients=recipients,
    )


def send_email(settings: EmailSettings, subject: str, body: str, timeout: float) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.sender
    msg["To"] = ", ".join(settings.recipients)
    msg.set_content(body)
    context = ssl.create_default_context()
    if settings.security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.host, settings.port, timeout=timeout, context=context
        )
    else:
        client = smtplib.SMTP(settings.host, settings.port, timeout=timeout)
    with client:
        client.ehlo()
        if settings.security == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if settings.user and settings.password:
            client.login(settings.user, settings.password)
        client.send_message(msg)


@dataclass
class Result:
    channel: str
    ok: bool
    error: str = ""


class Notifier:
    def __init__(self, config: NotifyConfig) -> None:
        self.config = config
        self._recent: dict[str, float] = {}

    def is_duplicate(self, key: str, now: float) -> bool:
        last = self._recent.get(key)
        if last is not None and now - last < self.config.dedupe_window_s:
            return True
        self._recent[key] = now
        return False

    def subject(self, i: Incident) -> str:
        return f"{self.config.subject_prefix} {i.severity.upper()}: {i.title}"

    async def send(self, incident: Incident, *, escalation: int = 0) -> list[Result]:
        text = render_text(incident)
        subject = self.subject(incident)
        if escalation:
            subject = f"{self.config.subject_prefix} ESCALATION {escalation}: {incident.title}"
            text = f"Nobody has acknowledged this incident yet.\n\n{text}"
        return await self.deliver(subject, text, {"incident": incident.__dict__, "text": text})

    async def deliver(self, subject: str, text: str, payload: dict[str, Any]) -> list[Result]:
        """Send one message to every configured channel. Failures come back, they never raise."""
        results: list[Result] = []
        if self.config.email:
            settings = email_settings()
            if settings is None:
                results.append(Result("email", False, "SMTP_HOST or ALERT_EMAIL_TO not set"))
            else:
                try:
                    await asyncio.to_thread(
                        send_email, settings, subject, text, self.config.timeout_s
                    )
                    results.append(Result("email", True))
                except Exception as exc:  # never let a mail problem, or its text, leak or crash
                    results.append(Result("email", False, type(exc).__name__))
        url = self.config.webhook_url or os.environ.get("ALERT_WEBHOOK_URL")
        if url:
            try:
                async with httpx.AsyncClient(timeout=self.config.timeout_s) as client:
                    resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                results.append(Result("webhook", True))
            except Exception as exc:
                results.append(Result("webhook", False, type(exc).__name__))
        return results
