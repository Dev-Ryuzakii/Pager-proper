"""Who may be put back into a live call after a client dropped mid-switch."""

_REMOVED = {"denied", "removed"}


def can_revive_original_caller(kind, status) -> bool:
    """Only the original callers of a 1:1 call, and never after the host denied them."""
    return kind == "call" and (status or "") not in _REMOVED
