"""TLS key-exchange profiles for the edge side.

OpenSSL reads its config once, at library initialisation. Python initialises it
when `ssl` is first imported, so the profile has to be in place BEFORE that.
`ensure_profile()` therefore writes a tiny openssl.cnf and re-executes the
current process with OPENSSL_CONF pointing at it (once).
"""
import os
import sys
import tempfile

# profile name -> OpenSSL `Groups` string (same strings as gateway/openssl-*.cnf)
PROFILES = {
    "classical": "X25519:secp256r1",
    "hybrid": "X25519MLKEM768:X25519",
    "pqc": "MLKEM768",
}

_MARK = "_PQC_PROFILE_APPLIED"


def cnf_text(profile):
    groups = PROFILES[profile]
    return (
        "openssl_conf = openssl_init\n"
        "[openssl_init]\nssl_conf = ssl_sect\n"
        "[ssl_sect]\nsystem_default = sd\n"
        "[sd]\nMinProtocol = TLSv1.3\nGroups = %s\n" % groups
    )


def ensure_profile(profile):
    """Re-exec this process with the chosen profile if it is not active yet."""
    if profile not in PROFILES:
        raise SystemExit("unknown profile %r (choose from %s)"
                         % (profile, ", ".join(PROFILES)))
    if os.environ.get(_MARK) == profile:
        return
    fd, path = tempfile.mkstemp(prefix="openssl-%s-" % profile, suffix=".cnf")
    with os.fdopen(fd, "w") as fh:
        fh.write(cnf_text(profile))
    env = dict(os.environ, OPENSSL_CONF=path, **{_MARK: profile})
    os.execve(sys.executable, [sys.executable] + sys.argv, env)
