import logging
import sys

def setup_logging(level=logging.INFO):
    """Configure root logger for the backend app."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    # silence noisy libraries if needed
    logging.getLogger("psycopg").setLevel(logging.WARNING)
    logging.getLogger("cryptography").setLevel(logging.WARNING)

