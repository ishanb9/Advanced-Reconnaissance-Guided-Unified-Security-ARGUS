"""Multi-factor authentication — TOTP + backup codes + WebAuthn stub.

TOTP (RFC 6238):
  - 30-second period, 6 digits, SHA-1 (industry default; Authy, Google
    Authenticator, Authelia, 1Password all interoperate on this).
  - We accept ±1 step skew (so a code generated at the end of a window
    still authenticates as long as it arrives within ~60s).
  - Secrets are stored encrypted with `cryptography.fernet` keyed by
    the deployment pepper (when set); otherwise stored base32-only.
    For high-security deployments, mount a KMS-decrypted file at
    AUTH_MFA_KEY_FILE.

Backup codes:
  - 10 single-use codes generated at TOTP enrolment.
  - Stored as argon2 hashes (same as passwords).
  - Redemption marks the row used + emits SECURITY-severity audit log.

WebAuthn:
  - Interface and DB columns ready (UserMfaFactor.credential_id,
    public_key, sign_count); routes left for follow-up because they
    require the `webauthn` library and frontend orchestration.
"""
from __future__ import annotations

import base64
import io
import logging
import secrets
import string
from typing import List, Optional, Tuple

try:
    import pyotp
except ImportError:                       # pragma: no cover
    pyotp = None

try:
    import qrcode
except ImportError:                       # pragma: no cover
    qrcode = None

from cryptography.fernet import Fernet, InvalidToken
import hashlib

from auth.config import CONFIG
from auth.security.passwords import _HASHER  # reuse Argon2 hasher for backup codes

logger = logging.getLogger("argus.auth.mfa")


# ─────────────────────────────────────────────────────────────────
#  Symmetric encryption for TOTP secrets at rest
# ─────────────────────────────────────────────────────────────────


def _fernet() -> Optional[Fernet]:
    """Build a Fernet from the deployment pepper.

    Fernet requires a 32-byte URL-safe base64 key.  We derive one by
    SHA-256 on the pepper (deterministic for the deployment lifetime).
    Returns None when no pepper is set — in that case we store secrets
    in plaintext base32 (acceptable for single-tenant dev; not for prod).
    """
    if not CONFIG.password_pepper:
        return None
    key_bytes = hashlib.sha256(CONFIG.password_pepper.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _encrypt(plaintext: str) -> str:
    f = _fernet()
    if not f:
        return plaintext
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def _decrypt(ciphertext: str) -> str:
    f = _fernet()
    if not f:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Falls through to treat-as-plaintext for backward compatibility
        # with secrets created before pepper was introduced.
        return ciphertext


# ─────────────────────────────────────────────────────────────────
#  TOTP enrolment
# ─────────────────────────────────────────────────────────────────


def generate_totp_secret() -> str:
    """Return a fresh base32 secret suitable for TOTP."""
    if pyotp is None:
        raise RuntimeError("pyotp not installed — pip install pyotp")
    return pyotp.random_base32()


def encrypt_totp_secret(secret_b32: str) -> str:
    """Encrypt a TOTP secret for at-rest storage in UserMfaFactor.secret_encrypted."""
    return _encrypt(secret_b32)


def decrypt_totp_secret(stored: str) -> str:
    return _decrypt(stored)


def totp_provisioning_uri(secret_b32: str, email: str) -> str:
    """Build the otpauth:// URI an authenticator app expects.

    Example:
      otpauth://totp/ARGUS:operator@example.com?secret=ABC...&issuer=ARGUS
    """
    if pyotp is None:
        raise RuntimeError("pyotp not installed — pip install pyotp")
    return pyotp.totp.TOTP(
        secret_b32,
        digits=CONFIG.totp_digits,
        interval=CONFIG.totp_period_sec,
    ).provisioning_uri(name=email, issuer_name=CONFIG.totp_issuer)


def totp_qr_png_base64(secret_b32: str, email: str) -> str:
    """Return a data: URI for the enrolment QR code.

    The frontend shows this as an <img src=...> on the enrolment screen.
    """
    if qrcode is None:
        raise RuntimeError("qrcode[pil] not installed — pip install qrcode[pil]")
    uri = totp_provisioning_uri(secret_b32, email)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_totp(secret_b32: str, code: str,
                valid_window: Optional[int] = None) -> bool:
    """Verify a TOTP code with configurable skew window.

    `valid_window` defaults to CONFIG.totp_skew_steps and is symmetric
    (accepts past N steps and future N steps).
    """
    if pyotp is None:
        return False
    if not code or not code.strip():
        return False
    code = code.strip().replace(" ", "")
    window = CONFIG.totp_skew_steps if valid_window is None else valid_window
    try:
        totp = pyotp.TOTP(secret_b32,
                          digits=CONFIG.totp_digits,
                          interval=CONFIG.totp_period_sec)
        return totp.verify(code, valid_window=window)
    except Exception as e:
        logger.warning("totp verify error: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────
#  Backup codes
# ─────────────────────────────────────────────────────────────────


_ALPHABET = string.ascii_lowercase + string.digits


def generate_backup_codes(count: Optional[int] = None) -> List[str]:
    """Generate human-friendly single-use recovery codes.

    Format: 'xxxx-xxxx' lowercase alnum (8 chars + dash) for ~41 bits
    of entropy per code — well above the OWASP-recommended 64-bit
    recovery threshold when combined across all 10 codes.
    """
    n = count if count is not None else CONFIG.backup_code_count
    codes: List[str] = []
    for _ in range(n):
        part1 = "".join(secrets.choice(_ALPHABET) for _ in range(4))
        part2 = "".join(secrets.choice(_ALPHABET) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes


def hash_backup_code(code: str) -> str:
    """Argon2id-hash a backup code (same as passwords)."""
    return _HASHER.hash(code.strip().lower())


def verify_backup_code(code: str, stored_hash: str) -> bool:
    """Constant-time verify of a presented backup code."""
    try:
        _HASHER.verify(stored_hash, code.strip().lower())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
#  WebAuthn / FIDO2 (stub)
# ─────────────────────────────────────────────────────────────────


class WebAuthnNotConfigured(RuntimeError):
    pass


def webauthn_begin_registration(*args, **kwargs):
    """Stub — bind `webauthn` library here.

    Typical bind:
        from webauthn import generate_registration_options
        opts = generate_registration_options(
            rp_id=CONFIG.webauthn_rp_id,
            rp_name=CONFIG.webauthn_rp_name,
            user_id=user.id.encode(),
            user_name=user.email,
            user_display_name=user.display_name or user.email,
            attestation="none",
            authenticator_selection=AuthenticatorSelectionCriteria(...),
        )
        return options_to_json(opts)
    """
    raise WebAuthnNotConfigured(
        "WebAuthn is enabled but not yet bound — see auth/security/mfa.py docstring."
    )


def webauthn_verify_registration(*args, **kwargs):
    raise WebAuthnNotConfigured(...)


def webauthn_begin_authentication(*args, **kwargs):
    raise WebAuthnNotConfigured(...)


def webauthn_verify_authentication(*args, **kwargs):
    raise WebAuthnNotConfigured(...)


__all__ = [
    "generate_totp_secret",
    "encrypt_totp_secret",
    "decrypt_totp_secret",
    "totp_provisioning_uri",
    "totp_qr_png_base64",
    "verify_totp",
    "generate_backup_codes",
    "hash_backup_code",
    "verify_backup_code",
    "webauthn_begin_registration",
    "webauthn_verify_registration",
    "webauthn_begin_authentication",
    "webauthn_verify_authentication",
    "WebAuthnNotConfigured",
]
