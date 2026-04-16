"""Custom exceptions for Joern CPG analysis."""


class JoernConnectionError(Exception):
    """Raised when the Joern server is unreachable."""
    pass


class JoernQueryError(Exception):
    """Raised when a Joern Scala query fails or returns unexpected output."""
    pass
