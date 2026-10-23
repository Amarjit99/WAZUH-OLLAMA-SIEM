"""TLS context factory providing strict certificate and hostname verification."""

import os
import ssl
from typing import Optional


def build_ssl_context(ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Build a strict TLS context with explicit CA bundle and hostname verification.
    
    Ensures certificate-chain and hostname checks are always active.
    Clears VERIFY_X509_STRICT to support local CAs generated without keyUsage extension.
    """
    if ca_file and os.path.isfile(ca_file):
        ctx = ssl.create_default_context(cafile=ca_file)
    else:
        ctx = ssl.create_default_context()

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

    return ctx
