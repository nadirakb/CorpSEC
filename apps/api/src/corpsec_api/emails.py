"""Email texts. Plain language, short, one clear action (same rules as explanations)."""

from __future__ import annotations

from collections.abc import Sequence

from corpsec_api.mailer import Mail


def magic_link(to: str, link: str, minutes: int) -> Mail:
    return Mail(
        to=to,
        subject="Your CorpSEC sign-in link",
        text=(
            "Hello,\n\n"
            "Click this link to sign in to CorpSEC:\n\n"
            f"{link}\n\n"
            f"The link works once and expires in {minutes} minutes.\n"
            "If you didn't ask for it, you can ignore this email.\n\n"
            "CorpSEC"
        ),
    )


def grade_drop(to: str, domain: str, old: str, new: str, link: str) -> Mail:
    return Mail(
        to=to,
        subject=f"{domain}: security grade dropped from {old} to {new}",
        text=(
            f"Hello,\n\nOur weekly check of {domain} found new problems. "
            f"Your grade went from {old} to {new}.\n\n"
            f"See what changed and how to fix it:\n{link}\n\nCorpSEC"
        ),
    )


def new_problems(to: str, domain: str, titles: Sequence[str], link: str) -> Mail:
    lines = "\n".join(f"  - {t}" for t in titles)
    return Mail(
        to=to,
        subject=f"{domain}: new security problem found",
        text=(
            f"Hello,\n\nOur check of {domain} found something new:\n\n{lines}\n\n"
            f"See the steps to fix it:\n{link}\n\nCorpSEC"
        ),
    )


def expiring(to: str, domain: str, what: str, days: int, link: str) -> Mail:
    noun = {"cert": "security certificate", "domain": "domain registration"}[what]
    return Mail(
        to=to,
        subject=f"{domain}: your {noun} expires in {days} days",
        text=(
            f"Hello,\n\nThe {noun} for {domain} expires in {days} days. "
            "When it does, visitors will see a warning or the site will stop working.\n\n"
            f"How to renew it:\n{link}\n\nCorpSEC"
        ),
    )


def site_down(to: str, domain: str, link: str) -> Mail:
    return Mail(
        to=to,
        subject=f"{domain}: we couldn't reach your website",
        text=(
            f"Hello,\n\nWe tried to open {domain} and it didn't answer. "
            "If you didn't take it down on purpose, contact your web host.\n\n"
            f"{link}\n\nCorpSEC"
        ),
    )


def verification_lost(to: str, domain: str, link: str) -> Mail:
    return Mail(
        to=to,
        subject=f"{domain}: monitoring paused",
        text=(
            f"Hello,\n\nWe couldn't confirm that you still own {domain} (we checked twice). "
            "We paused weekly checks for now.\n\n"
            f"To start again, verify the site once more:\n{link}\n\nCorpSEC"
        ),
    )


def share_report(
    to: str,
    sender: str,
    domain: str,
    grade: str | None,
    top: Sequence[str],
    link: str,
    note: str | None,
) -> Mail:
    fixes = "\n".join(f"  {i}. {t}" for i, t in enumerate(top, 1)) or "  (nothing urgent)"
    personal = f"\nMessage from {sender}:\n{note}\n" if note else ""
    return Mail(
        to=to,
        subject=f"Security report for {domain} (grade {grade or '?'})",
        text=(
            f"Hello,\n\n{sender} shared a CorpSEC security report for {domain} with you.\n"
            f"{personal}\n"
            f"Grade: {grade or 'not graded'}\n\nWhat to fix first:\n{fixes}\n\n"
            f"Full report with technical details and evidence:\n{link}\n\n"
            "The link is read-only. It works for 30 days.\n\nCorpSEC"
        ),
    )
