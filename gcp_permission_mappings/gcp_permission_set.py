import json

from gcp_permission_mappings.gcp_permission import GcpPermission
from gcp_permission_mappings.util import *
from importlib import resources
from typing import Optional


# Represents a set of abstract GCP permissions. Adding different representations
# of the same permission should reconcile automatically
class GcpPermissionSet:
    def __init__(self):
        self._permissions_dict: dict[int, GcpPermission] = {}

    @property
    def permissions(self):
        return list(self._permissions_dict.values())

    # Add a permission to the set by name. If the permission already exists
    # in the set (i.e. we add a V2 permission, but the V1 already exists),
    # we combine
    def add_permission(self, permission_name: str, deny_support: bool = False):
        permission = GcpPermission(permission_name, deny_support)
        if permission.__hash__() in self._permissions_dict:
            self._permissions_dict[permission.__hash__()].combine(permission)
        else:
            self._permissions_dict[permission.__hash__()] = permission

    # If there are non-standard V2 -> V1 mappings, we need to take the V2 and V1
    # versions of the permission in the set and combine them. This must be run
    # after both permissions are loaded.
    def dedupe_non_standard_mapping(self, v1: str, v2: str):
        v1_key = GcpPermission(v1).__hash__()
        v2_key = GcpPermission(v2).__hash__()

        if v1_key not in self._permissions_dict or \
                v2_key not in self._permissions_dict:
            return

        v1 = self._permissions_dict[v1_key]
        v2 = self._permissions_dict[v2_key]

        v2.v1_override = v1.as_v1()
        v2.has_v1 = True
        del self._permissions_dict[v1_key]

    def contains(self, permission: str) -> bool:
        return GcpPermission(permission).__hash__() in self._permissions_dict \
            or any(p.v1_override == permission for p in self.permissions)

    def get(self, permission: str) -> Optional[GcpPermission]:
        if not GcpPermission(permission).__hash__() in self._permissions_dict:
            if any(p.v1_override == permission for p in self.permissions):
                return next(p for p in self.permissions if p.v1_override == permission)
            return None
        else:
            return self._permissions_dict[GcpPermission(permission).__hash__()]


def load_permission_set(live=False):
    if live:
        return load_live_permission_set()
    else:
        return load_static_permission_set()


def load_static_permission_set():
    resources_folder = resources.files('gcp_permission_mappings').joinpath('resources')
    permission_set = GcpPermissionSet()

    allowable_file = resources_folder / 'allowable_permissions.json'
    with allowable_file.open() as f:
        allowable_permissions = json.load(f)
        for service, permission_list in allowable_permissions.items():
            for permission in permission_list:
                permission_set.add_permission(permission, deny_support=False)

    deniable_file = resources_folder / 'deniable_permissions.json'
    with deniable_file.open() as f:
        deniable_permissions = json.load(f)
        for service, permission_list in deniable_permissions.items():
            for permission in permission_list:
                permission_set.add_permission(permission, deny_support=True)

    mapping_file = resources_folder / 'non_standard_mappings.json'
    with mapping_file.open() as f:
        v2_to_v1_map = json.load(f)
        for v2, v1 in v2_to_v1_map.items():
            permission_set.dedupe_non_standard_mapping(v1, v2)

    return permission_set


def load_live_permission_set():
    allowable_permissions = get_allowable_permissions()
    deniable_permissions = get_deniable_permissions()
    v2_to_v1_map = get_non_standard_permission_map()

    permission_set = GcpPermissionSet()

    for permission in allowable_permissions:
        permission_set.add_permission(permission, deny_support=False)
    for permission in deniable_permissions:
        permission_set.add_permission(permission, deny_support=True)
    for v2, v1 in v2_to_v1_map.items():
        permission_set.dedupe_non_standard_mapping(v1, v2)

    return permission_set
