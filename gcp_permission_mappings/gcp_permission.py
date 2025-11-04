import re
from typing_extensions import Self


# Represents an abstract GCP permission, which may have both a V1 API and V2 API
# representation. Some permissions can be translated directly from V1 to V2 by
# adding ".googleapis.com/" to the service, but other times this does not work.
#
# Exceptions can be scraped from
# https://cloud.google.com/iam/docs/deny-permissions-support
class GcpPermission:

    @staticmethod
    def is_v2_name(permission: str):
        return '.googleapis.com/' in permission

    @staticmethod
    def v2_to_v1(permission: str):
        if not GcpPermission.is_v2_name(permission):
            raise ValueError('{} is not a V2 GCP permission'.format(permission))
        return permission.replace('.googleapis.com/', '.')

    def __init__(self, permission_name, deny_support=False):
        self.has_v1 = False
        self.has_v2 = False
        self.v1_override = None
        self.deny_support = deny_support

        if '.googleapis.com/' in permission_name:
            self.has_v2 = True
            match = re.search(r'(.+)\.googleapis\.com/(.+)', permission_name)
            [service, action] = match.groups()
        else:
            self.has_v1 = True
            [service, action] = permission_name.split('.', 1)

        self.service = service
        self.action = action

        # TODO Error handling:
        # - Ensure it meets either V1 or V2 spec
        # - Ensure either meets V2 or deny support is false

    def __eq__(self, other: Self):
        return self.service == other.service and self.action == other.action

    def __hash__(self):
        return hash((self.service, self.action))

    def __lt__(self, other: Self):
        if self.service != other.service:
            return self.service < other.service
        return self.action < other.action

    def combine(self, other: Self):
        self.has_v1 |= other.has_v1
        self.has_v2 |= other.has_v2
        self.deny_support |= other.deny_support
        if not self.v1_override:
            self.v1_override = other.v1_override

    def as_v1(self):
        if not self.has_v1:
            return None

        if self.v1_override:
            return self.v1_override

        return '{}.{}'.format(self.service, self.action)

    def as_v2(self):
        if not self.has_v2:
            return None

        return '{}.googleapis.com/{}'.format(self.service, self.action)
