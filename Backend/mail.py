"""Optional outbound mail for password-reset delivery.

When SMTP is unconfigured the platform reports that reset e-mail delivery is
unavailable rather than silently dropping or faking delivery.
"""
import logging
import smtplib
from email.mime.text import MIMEText

from . import config

logger = logging.getLogger("NIDS.Mail")


def configured() -> bool:
    return bool(config.SMTP_HOST)


def send_reset_email(to_email: str, reset_url: str) -> bool:
    if not configured():
        return False
    msg = MIMEText(
        f"A password reset was requested for your Cybersecurity Analyst Workbench account.\n\n"
        f"Open this link to choose a new password (single use, expires in "
        f"{config.PASSWORD_RESET_TTL_SECONDS // 60} minutes):\n{reset_url}\n\n"
        f"If you did not request this, ignore this message.\n"
    )
    msg["Subject"] = "Password reset - Cybersecurity Analyst Workbench"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as smtp:
            if config.SMTP_STARTTLS:
                smtp.starttls()
            if config.SMTP_USERNAME:
                smtp.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        # Never log credentials; the exception text from smtplib contains none.
        logger.warning("Password-reset e-mail delivery failed: %s", e)
        return False
