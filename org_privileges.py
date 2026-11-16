"""Organization-wide privileges. One copy so channel and meeting checks cannot drift."""

ORG_PRIVILEGES = {
    "broadcast", "assign_tasks", "call_control", "manage_staff", "manage_groups", "approve_deletions",
}


def is_org_account(user) -> bool:
    """The organization account itself. A portal-only viewer is not this account."""
    return getattr(user, "user_type", None) == "organization"


def org_privilege_set(user) -> set:
    """Site admins and the organization account hold every privilege."""
    if getattr(user, "is_admin", False) or is_org_account(user):
        return set(ORG_PRIVILEGES)
    raw = getattr(user, "org_privileges", None) or []
    if "*" in raw:
        return set(ORG_PRIVILEGES)
    return {p for p in raw if p in ORG_PRIVILEGES}


def has_org_privilege(user, name: str) -> bool:
    return name in org_privilege_set(user)
