"""Email utilities for Sentinel follow-ups."""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)


def _sendgrid_from(value: str) -> dict[str, str]:
    raw = (value or "").strip()
    if "<" in raw and ">" in raw:
        name = raw.split("<", 1)[0].strip().strip('"')
        email = raw.split("<", 1)[1].split(">", 1)[0].strip()
        return {"email": email, "name": name} if name else {"email": email}
    return {"email": raw}


def send_follow_up_reminder(
    to_email: str,
    action_text: str,
    remind_at: str,
    to_name: str | None = None,
    message: str | None = None,
) -> bool:
    """Send a follow-up reminder email via SendGrid or Resend."""

    subject = f"Sentinel Reminder: {action_text[:50]}{'...' if len(action_text) > 50 else ''}"

    # Modern, clean HTML template
    html_content = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: auto; padding: 32px; border: 1px solid #e5e7eb; border-radius: 12px; color: #1f2937;">
        <div style="margin-bottom: 24px;">
            <span style="background: #6366f1; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">Sentinel AI</span>
        </div>
        <h2 style="margin: 0 0 16px; font-size: 20px; font-weight: 700; color: #111827;">Incident Follow-up</h2>
        <p style="margin: 0 0 24px; font-size: 15px; line-height: 1.5; color: #4b5563;">
            Hi {to_name or 'Engineer'},<br/><br/>
            This is a scheduled reminder for a remediation action you are tracking in Sentinel.
        </p>
        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin-bottom: 24px;">
            <strong style="display: block; font-size: 12px; text-transform: uppercase; color: #6b7280; letter-spacing: 0.05em; margin-bottom: 8px;">Remediation Task</strong>
            <div style="font-size: 15px; font-weight: 500; color: #1f2937; line-height: 1.5;">{action_text}</div>
        </div>
        {f'<div style="margin-bottom: 24px;"><strong style="display: block; font-size: 12px; text-transform: uppercase; color: #6b7280; letter-spacing: 0.05em; margin-bottom: 8px;">Operator Note</strong><div style="font-size: 14px; font-style: italic; color: #4b5563; border-left: 3px solid #d1d5db; padding-left: 12px;">{message}</div></div>' if message else ''}
        <p style="margin: 32px 0 0; font-size: 12px; color: #9ca3af; line-height: 1.5;">
            Scheduled for: {remind_at}<br/>
            Sent by Sentinel AI Incident Intelligence.
        </p>
    </div>
    """

    sendgrid_key = os.getenv("SENDGRID_API_KEY")
    if sendgrid_key:
        from_addr = (
            os.getenv("SENDGRID_FROM")
            or os.getenv("SENDGRID_SENDER_EMAIL")
            or os.getenv("RESEND_FROM")
            or "Sentinel <onboarding@resend.dev>"
        )
        try:
            response = httpx.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {sendgrid_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "personalizations": [{"to": [{"email": to_email}]}],
                    "from": _sendgrid_from(from_addr),
                    "subject": subject,
                    "content": [{"type": "text/html", "value": html_content}],
                },
                timeout=10.0,
            )
            response.raise_for_status()
            logger.info("Successfully sent follow-up email via SendGrid to %s", to_email)
            return True
        except Exception as e:
            logger.error("Failed to send SendGrid email to %s: %s", to_email, str(e))
            return False

    api_key = os.getenv("RESEND_API_KEY")
    from_addr = os.getenv("RESEND_FROM", "Sentinel <onboarding@resend.dev>")

    if not api_key:
        logger.warning("SENDGRID_API_KEY/RESEND_API_KEY not set, skipping email for %s", to_email)
        return False

    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_addr,
                "to": to_email,
                "subject": subject,
                "html": html_content,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        logger.info("Successfully sent follow-up email to %s", to_email)
        return True
    except Exception as e:
        logger.error("Failed to send email to %s: %s", to_email, str(e))
        return False
