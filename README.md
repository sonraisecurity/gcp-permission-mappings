# gcp-permission-mappings

A utility for compiling and exploring the complete set of abstract GCP permissions and their various (IAM V1, IAM V2, etc.) representations. This is intended primarily an education and research tool, and its use has not been tested in production environments.

If you just want to see the V1/V2 representations of each permission and check for deny support without playing around in Python, check out [mappings.json](mappings.json).

## Usage Examples:

### Answering questions about the set of all GCP permissions

1. Show me all GCP Permissions, their various representations, and their support levels in deny policies

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> for permission in permission_set.permissions:
    ...     print(permission.describe())
    ...
    {'V1': 'metastore.tables.create', 'V2': None, 'Deny Policy Support': False}
    {'V1': 'metastore.tables.delete', 'V2': 'metastore.googleapis.com/tables.delete', 'Deny Policy Support': True}
    {'V1': 'metastore.tables.get', 'V2': None, 'Deny Policy Support': False}
    {'V1': 'metastore.tables.list', 'V2': None, 'Deny Policy Support': False}
    {'V1': 'metastore.tables.update', 'V2': 'metastore.googleapis.com/tables.update', 'Deny Policy Support': True}
    ```

2. Show me permission counts by support in deny policies

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>>
    >>> len(permission_set.permissions)  # Total number of GCP permissions
    12379
    >>> len([p for p in permission_set.permissions if p.deny_support])  # Number of deniable GCP permissions
    5335
    >>> len([p for p in permission_set.permissions if not p.deny_support])  # Number of non-deniable GCP permissions
    7044
    ```

3. Show me permissions with non-standard V1 -> V2 mappings (i.e. service namespace changes)

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> for permission in permission_set.permissions:
    ...     if permission.v1_override:
    ...         print(permission.describe())
    ...
    {'V1': 'serviceusage.apiKeys.regenerate', 'V2': 'apikeys.googleapis.com/apiKeys.regenerate', 'Deny Policy Support': True}
    {'V1': 'serviceusage.apiKeys.revert', 'V2': 'apikeys.googleapis.com/apiKeys.revert', 'Deny Policy Support': True}
    {'V1': 'bigquery.connections.create', 'V2': 'bigqueryconnection.googleapis.com/connections.create', 'Deny Policy Support': True}
    {'V1': 'bigquery.connections.delegate', 'V2': 'bigqueryconnection.googleapis.com/connections.delegate', 'Deny Policy Support': True}
    {'V1': 'bigquery.connections.delete', 'V2': 'bigqueryconnection.googleapis.com/connections.delete', 'Deny Policy Support': True}
    ```

4. Show me permissions that require using V2 representations in role definitions

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> for permission in permission_set.permissions:
    ...     if not permission.has_v1:
    ...         print(permission.describe())
    ...
    {'V1': None, 'V2': 'bigqueryreservation.googleapis.com/bireservations.get', 'Deny Policy Support': False}
    {'V1': None, 'V2': 'bigqueryreservation.googleapis.com/bireservations.update', 'Deny Policy Support': False}
    {'V1': None, 'V2': 'bigqueryreservation.googleapis.com/capacityCommitments.create', 'Deny Policy Support': False}
    {'V1': None, 'V2': 'bigqueryreservation.googleapis.com/capacityCommitments.delete', 'Deny Policy Support': False}
    {'V1': None, 'V2': 'bigqueryreservation.googleapis.com/capacityCommitments.get', 'Deny Policy Support': False}
    ```

### Answering permission-specific questions

1. Is a V1 Permission deniable, and if so, how is it referenced?

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> 
    >>> permission = permission_set.get('iam.roles.create')
    >>> permission.deny_support  # Is 'iam.roles.create' deniable?
    True
    >>> permission.as_v2()  # What is it's V2 representation for the deny policy?
    'iam.googleapis.com/roles.create'
    >>>
    >>> permission = permission_set.get('iam.denypolicies.create')
    >>> permission.deny_support  # Is 'iam.denypolicies.create' deniable?
    False
    ```

2. Given a permission in a deny policy, what is the V1 representation in role definitions?

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> 
    >>> permission_set.get('iam.googleapis.com/roles.create').as_v1()
    'iam.roles.create'
    >>> permission_set.get('apikeys.googleapis.com/apiKeys.regenerate').as_v1()
    'serviceusage.apiKeys.regenerate'
   ```

3. Does a permission (in any form) exist?

    ```python
    >>> from gcp_permission_mappings import load_permission_set
    >>> permission_set = load_permission_set()
    >>> 
    >>> permission_set.contains('iam.roles.create')
    True
    >>> permission_set.contains('iam.googleapis.com/denypolicies.create')
    True
    >>> permission_set.contains('iam.googleapis.com/someresource.someaction')
    False
    >>> permission_set.contains('string')
    False
    ```

## Using Live Data

By default, calling `gcp_permission_mappings.load_permission_set` will build it's set of GCP permissions from the permissions and permission mappings stored in `./gcp_permision_mappings/resources/*.json`.

There *is* an optional `live` parameter that, when set to `true`, pulls content directly from the GCP docs rather than from the bundled content. As Google updates their set of available permissions on a near-daily basis, this will get you the most up-to-date content.

Sample:
```python
 >>> from gcp_permission_mappings import load_permission_set
 >>> permission_set = load_permission_set(live=True)
 >>> 
 >>> permission_set.contains('iam.roles.create')
 True
```

No matter how much effort we put into keeping the bundled permissions up-to-date, loading from the live Google data will almost always produce a more complete set of permissions than the bundled content:
```python
 >>> from gcp_permission_mappings import load_permission_set
 >>> static_set = load_permission_set()
 >>> live_set = load_permission_set(live=True)
 >>> 
 >>> len(static_set.permissions)
 12379
 >>> len(live_set.permissions)
 12452
```

Sources:

- [Permissions Supported in Deny Policies](https://cloud.google.com/iam/docs/deny-permissions-support)
- [Support levels for permissions in custom roles](https://cloud.google.com/iam/docs/custom-roles-permissions-support)
- [IAM roles and permissions index](https://cloud.google.com/iam/docs/roles-permissions)

Some words of warning:

- This set takes quite a bit longer to load
- The permission collection is a bit finicky, as we pull from the doc contents rather than a standard API. This may break at some point in the future if Google changes the structure of their docs

## Implementation Details (the Python Classes)

### GcpPermission

Represents an abstract GCP privilege, independent of its various string representations

| property     | type   | description                                                                                                                                |
|--------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------|
| service      | string | The IAM namespace the permission belongs to. If there's a mismatch between V1/V2, this property refers to the service of the V2 permission |
| action       | string | The `<resource>.<action>` component of the permission, common to both V1 and V2 representations                                            |
| has_v1       | bool   | whether the permission has a V1 representation                                                                                             |
| has_v1       | bool   | whether the permission has a V2 representation                                                                                             |
| deny_support | bool   | whether the permission is supported in deny policies. Note, not all permissinos with V2 representations are supported in deny policies     |
| v1_override  | string | The V1 representation of the permission if it's not a standard mapping (i.e. service namespace is different                                |

| method         | return type | description                                                                                                                                               |
|----------------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| combine(other) | -           | Combines a GcpPermission with another representing the same permission. Used in a `GcpPermissionSet` to aggregate V1 and V2 permissions loaded separately |
| describe()     | dict        | Returns a dictionary showing the V1 and V2 representations of a permission if they exist, and whether a permission is supported in deny policies          |
| as_v1()        | string      | Returns the V1 representation of a permission (None if it doesn't exist)                                                                                  |
| as_v2()        | string      | Returns the V2 representation of a permission (None if it doesn't exist)                                                                                  |

### GcpPermissionSet

Represents a collection of GCP privileges, independent of their various representations. Provides various methods to help aggregate representations of the same privilege together.

| property    | type                | description                                                   |
|-------------|---------------------|---------------------------------------------------------------|
| permissions | list[GcpPermission] | The list of GCP permissions represented by the permission set |

| method                                   | return type   | description                                                                                                                                                                                                                                                                                                                                              |
|------------------------------------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| contains(permission)                     | bool          | Given a permission string, returns whether the permission is included in the set                                                                                                                                                                                                                                                                         |
| get(permission)                          | GcpPermission | Get the GcpPermission object representing a given permission string                                                                                                                                                                                                                                                                                      |
| describe(permission)                     | dict          | Get a dictionary showing the V1 and V2 representations of a permission if the permission exists in the set, and whether it's supported in deny policies                                                                                                                                                                                                  |
| add_permission(permission, deny_support) | -             | Given the V1 or V2 representation of a permission, add it to the set. If the permission already exists in the set (e.g. the V1 has already been added, and now the V2 is being added), the entries are combined. Whether a permission is supported in deny policies needs to be set explicitely as not all V2 permissions are supported in deny policies |
| dedupe_non_standard_mapping(v1, v2)      | -             | Given the V1 and V2 representations of a permission, combine those permissions if both are already in the set. This is used to account for V1 -> V2 mappings where the service changes between IAM versions. This does not implicitely add a version of a permission to the set if it has not already been added via `add_permission`                    |