class ODTSError(RuntimeError):
    """Base ODTS error."""


class UnsupportedHostError(ODTSError):
    """Raised when the host platform cannot execute ODTS."""


class DependencyError(ODTSError):
    """Raised when a required dependency is unavailable."""


class DeviceStateError(ODTSError):
    """Raised when the connected device cannot be identified safely."""


class ExternalToolError(ODTSError):
    """Raised when an external binary fails validation or execution."""
