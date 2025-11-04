import json
import requests

from bs4 import BeautifulSoup


def get_allowable_permissions():
    """
    Loads live list of GCP permissions from the "IAM permissions reference" and
    "Support levels for permissions in custom roles" doc pages.
    """

    # Gets GCP permissions from the "IAM Roles and Permission Index" page
    # resources.
    response = requests.get('https://cloud.google.com/iam/json/role-permission-filter.json')
    response.raise_for_status()
    data = json.loads(response.text)
    permissions = {perm['title'] for perm in data['permissions']}

    # Gets GCP permissions from the "Support levels for permissions in custom
    # roles" doc page.
    response = requests.get('https://cloud.google.com/iam/docs/custom-roles-permissions-support')
    response.raise_for_status()
    codes = BeautifulSoup(response.text, 'html.parser').select('div#table-div-id > table:first-of-type > tbody:first-of-type td.column1-class > code:first-of-type')
    permissions |= {code.text for code in codes}

    return permissions


def get_deniable_permissions():
    """
    Loads live list of GCP permissions from the "Permissions supported in deny
    policies" doc page.
    """

    # Gets GCP permissions from the "Permissions supported in deny policies" doc
    response = requests.get('https://cloud.google.com/iam/docs/deny-permissions-support')
    response.raise_for_status()
    codes = BeautifulSoup(response.text, 'html.parser').select('table:first-of-type > tbody:first-of-type td > p:first-of-type > code:first-of-type')

    permissions = []
    for code in codes:
        if not code.text.endswith('*'):
            permissions.append(code.text)

    return permissions


def get_non_standard_permission_map():
    """
    Loads live set of GCP permissions from the "Permissions supported in deny
    policies" that have explicit mappings back to V1 permissions

    Keys are deny-supported V2 permissions, and values are V1 permissions:
    {
      "bigqueryconnection.googleapis.com/connections.getIamPolicy": "bigquery.connections.getIamPolicy",
      ...
    }
    """
    response = requests.get('https://cloud.google.com/iam/docs/deny-permissions-support')
    response.raise_for_status()
    permission_cells = BeautifulSoup(response.text, 'html.parser').select('table:first-of-type > tbody:first-of-type td')

    v2_v1_map = {}
    mapping_detector = 'In the IAM v1 API, this permission is named'
    for cell in permission_cells:
        code = cell.select_one('p:first-of-type > code:first-of-type')
        if not code:
            continue
        v2 = code.text

        # Whitespace is handled strangely in this doc... We need to ensure
        # there are single spaces only before we look for a note indicating a
        # V1 permission map
        aside = cell.select_one('aside', class_='note', recursive=False)
        if not aside or mapping_detector not in ' '.join(aside.text.split()):
            continue

        code = aside.find('code')
        if not code:
            raise Exception('Map found for {}, but v1 permission could not be '
                            'identified'.format(v2))

        v1 = code.text
        v2_v1_map[v2] = v1

    return v2_v1_map
