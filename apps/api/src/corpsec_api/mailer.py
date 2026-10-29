"""Outgoing email: magic links and alerts."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

from corpsec_api.settings import Settings

log = logging.getLogger("corpsec.mail")


@dataclass(frozen=True, slots=True)
class Mail:
    to: str
    subject: str
    text: str


class Mailer(Protocol):
    async def send(self, mail: Mail) -> None: ...


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def _send_sync(self, mail: Mail) -> None:
        msg = EmailMessage()
        msg["From"] = self._s.mail_from
        msg["To"] = mail.to
        msg["Subject"] = mail.subject
        msg.set_content(mail.text)
        assert self._s.smtp_host
        with smtplib.SMTP(self._s.smtp_host, self._s.smtp_port, timeout=20) as smtp:
            if self._s.smtp_starttls:
                smtp.starttls()
            if self._s.smtp_username:
                smtp.login(self._s.smtp_username, self._s.smtp_password or "")
            smtp.send_message(msg)

    async def send(self, mail: Mail) -> None:
        await asyncio.to_thread(self._send_sync, mail)


class LogMailer:
    """Development fallback when no SMTP server is configured."""

    async def send(self, mail: Mail) -> None:
        log.warning(
            "email (not sent, no SMTP configured) to=%s subject=%s\n%s",
            mail.to,
            mail.subject,
            mail.text,
        )


@dataclass
class MemoryMailer:
    """Tests: collects mail instead of sending it."""

    sent: list[Mail] = field(default_factory=list)

    async def send(self, mail: Mail) -> None:
        self.sent.append(mail)


def make_mailer(settings: Settings) -> Mailer:
    return SmtpMailer(settings) if settings.smtp_host else LogMailer()
