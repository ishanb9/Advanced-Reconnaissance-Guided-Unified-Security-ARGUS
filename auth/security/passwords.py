"""Argon2id password hashing — RFC 9106 parameters, with pepper rotation.

Why Argon2id over bcrypt:
  - Argon2id won the Password Hashing Competition (2015) and is the
    OWASP recommended default since 2021.
  - Memory-hard — resists GPU/ASIC brute force in ways bcrypt cannot.
  - Configurable in (time, memory, parallelism) so a single library
    can be tuned for both server-class boxes and constrained edges.
  - Built-in side-channel mitigation (the 'id' variant is hybrid).

Why a deployment pepper:
  - If the password-hash table leaks (SQLi, backup theft, insider) but
  the pepper does NOT (it lives in env or KMS), the attacker still
  cannot mount an offline crack — they're missing one of the inputs.

Verification is constant-time via argon2's `verify` (which raises
exceptions, not booleans, to avoid timing leaks).
"""
from __future__ import annotations

import hmac
import logging
from typing import Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from auth.config import CONFIG

logger = logging.getLogger("argus.auth.passwords")

# Cache the hasher — it's threadsafe and (re-)building it per-call
# would burn argon2's expensive parameter-validation phase.
_HASHER = PasswordHasher(
    time_cost   = CONFIG.argon2_time_cost,
    memory_cost = CONFIG.argon2_memory_cost,
    parallelism = CONFIG.argon2_parallelism,
)

# Dummy hash for unknown-user verifications — keeps response time
# constant whether the supplied email exists or not (anti-enumeration).
# Generated once at import; deterministic across processes is fine
# because it's compared only against attacker-controlled input.
_DUMMY_HASH = _HASHER.hash("dummy-password-for-timing-equalization")


# ─────────────────────────────────────────────────────────────────


def _apply_pepper(password: str, pepper: Optional[str] = None) -> str:
    """Mix the deployment-wide pepper into the password before hashing.

    Implementation: HMAC-SHA256(pepper, password).hex().  This is keyed
    so an attacker who learns the pepper cannot retroactively compute
    the un-peppered hash to match against a separate compromise.
    """
    pep = pepper if pepper is not None else CONFIG.password_pepper
    if not pep:
        return password
    return hmac.new(pep.encode("utf-8"), password.encode("utf-8"),
                    digestmod="sha256").hexdigest()


def hash_password(password: str) -> Tuple[str, int]:
    """Return (hash, pepper_version).

    `pepper_version` is recorded with the hash so on pepper rotation
    we know whether to re-hash on next successful login.  Current
    deployment uses version 1; rotation increments it.
    """
    _validate_length(password)
    peppered = _apply_pepper(password)
    return _HASHER.hash(peppered), 1


def verify_password(password: str, stored_hash: str,
                    pepper_version: int = 1) -> Tuple[bool, bool]:
    """Verify a password against a stored hash.

    Returns (ok, needs_rehash).  `needs_rehash` is True when:
      - the stored argon2 parameters are weaker than current config, OR
      - the pepper has been rotated and this hash uses an older pepper.

    Callers that get `needs_rehash=True` on a successful login should
    re-hash the supplied plaintext with `hash_password()` and update
    the row.
    """
    if not stored_hash:
        # Equalize timing — verify the dummy hash anyway
        try:
            _HASHER.verify(_DUMMY_HASH, _apply_pepper(password))
        except Exception:
            pass
        return False, False

    peppered = _apply_pepper(password)
    try:
        _HASHER.verify(stored_hash, peppered)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False, False
    except Exception as e:
        logger.warning("password verify: unexpected exception: %s", e)
        return False, False

    needs_rehash = (_HASHER.check_needs_rehash(stored_hash) or
                    pepper_version != 1)
    return True, needs_rehash


def constant_time_dummy_verify(password: str) -> None:
    """For unknown-email paths.  Burns the same CPU as a real verify
    so an attacker cannot tell from response time whether the email
    is in the system.
    """
    try:
        _HASHER.verify(_DUMMY_HASH, _apply_pepper(password))
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────
#  Password policy (NIST 800-63B compliant)
# ─────────────────────────────────────────────────────────────────


class PasswordPolicyError(ValueError):
    pass


def _validate_length(password: str) -> None:
    n = len(password)
    if n < CONFIG.password_min_length:
        raise PasswordPolicyError(
            f"Password must be at least {CONFIG.password_min_length} characters."
        )
    if n > CONFIG.password_max_length:
        raise PasswordPolicyError(
            f"Password must be at most {CONFIG.password_max_length} characters."
        )


def validate_policy(password: str, *,
                    email: Optional[str] = None,
                    username: Optional[str] = None) -> None:
    """Enforce NIST 800-63B §5.1.1.2.

    Rejections:
      • length out of bounds
      • contains the email local-part or username verbatim (case-insensitive)
      • is on the breached-password list (TODO: HIBP k-anon range query)

    The NIST guidance explicitly does NOT require character-class
    complexity (uppercase + number + symbol) — research shows those
    rules cause user-chosen passwords to weaken via predictable
    transformations.  We follow that guidance.
    """
    _validate_length(password)

    lower = password.lower()
    if email:
        local = email.split("@", 1)[0].lower()
        if local and local in lower:
            raise PasswordPolicyError(
                "Password cannot contain your email address."
            )
    if username and username.lower() in lower:
        raise PasswordPolicyError(
            "Password cannot contain your username."
        )

    # TODO: HIBP k-anon range query (sha1[:5] → list of suffixes)
    # We stub this for now since it requires network egress; in prod
    # bind a check via `pwned_passwords` lib or local downloaded list.


__all__ = [
    "hash_password",
    "verify_password",
    "constant_time_dummy_verify",
    "validate_policy",
    "PasswordPolicyError",
]
