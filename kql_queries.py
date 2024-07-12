# MIT License
# Copyright (c) 2024 Guido Hovens
# See the LICENSE file for more details.

from helpers import dict_empty, list_to_kql
from sigmaiq import SigmAIQBackend


query_to_abstract = {
    "basic_ipv4": " IPv4 Only Query",
    "basic_ipv6": " IPv6 Only Query",
    "basic_url": " Url Only Query",
    "url_in_email": " Url and Email Query",
    "basic_email": " Email Only Query",
    "basic_domain": " Domainname Only Query",
    "basic_hostname": " Hostname Only Query",
    "basic_file": " File Hash Only Query",
    "email_and_address": " Email and Address Query",
    "file_and_url": " Url and File Hash Query",
    "file_and_origin_ip": " File and origin IP Query",
    "file_and_remote_ip": " File and remote IP Query",
    "file_and_remote_url": " File and remote Url Query",
    "file_ip_and_url": " File, IP and Url Query",
    "file_and_process": " File and Process Query",
    "fileIP_and_FileUrl": " FileOriginIP and FileOriginUrl Query",
    "ip_and_file": " Process Hash connecting to ip Query",
    "sigma2kql": " Sigma to KQL Query",
}

def create_table_union(tables):
    """
    Creates a Kusto Query Language (KQL) table union based on a list of input tables.

    Args:
        tables (list): A list of KQL table names.

    Returns:
        str: A KQL table union string.
    """
    return "\n| union ".join(tables) if tables else ""


def or_condition(columns, values):
    """
    Creates a KQL OR condition based on a list of columns and a list of values.

    Args:
        columns (list): A list of KQL column names.
    
    Returns:
        str: A KQL OR condition string.
    """
    return "\n    or ".join([f"{column} in ({list_to_kql(values)})" for column in columns])

def hash_condition(columns, values):
    """
    Creates an or condition of all hashes in values that have the given algorithm.

    Args:
        columns (list): A list of KQL column names.
        values (list): A list of file hashes. For example [{algorithm: 'MD5', hash: '1234567890abcdef'}]
        algorithm (str): The hash algorithm.
    """
    filters = []
    algorithms = list({hash_dict['algorithm'] for hash_dict in values})
    for algorithm in algorithms:
        hashes = [hash_dict["hash"] for hash_dict in values if hash_dict['algorithm'] == algorithm]
        filters.append(or_condition([col + algorithm.replace("-", "") for col in columns], hashes))
    return "\n    or ".join(filters)


def create_queries(objects):
    """
    Generates Kusto Query Language (KQL) queries based on input objects.

    Args:
        objects (dict): A dictionary containing lists of IP addresses, email addresses, URLs, domain names, 
                        hostnames, and file hashes. Keys expected in the dictionary include:
                        - 'v4_addrs': List of IPv4 addresses.
                        - 'v6_addrs': List of IPv6 addresses.
                        - 'email_addrs': List of email addresses.
                        - 'urls': List of URLs.
                        - 'domain_names': List of domain names.
                        - 'hostnames': List of hostnames.
                        - 'hashes': List of dictionaries with 'hash' keys for file hashes.

    Returns:
        dict: A dictionary where keys are query identifiers (e.g., 'basic_ipv4', 'basic_email') and values 
              are the corresponding KQL query strings.
    """
    if dict_empty(objects):
        return

    backend = SigmAIQBackend(backend="microsoft365defender").create_backend()

    queries = {
        'basic_ipv4': create_table_union(["DeviceEvents", "DeviceNetworkEvents", "DeviceFileEvents", "EmailEvents"]),
        'basic_ipv6': create_table_union(["DeviceEvents", "DeviceNetworkEvents", "DeviceFileEvents", "EmailEvents"]),
        'ip_and_file': "DeviceNetworkEvents",
        'basic_url': create_table_union(["DeviceEvents", "DeviceNetworkEvents", "DeviceFileEvents", "EmailUrlInfo", "UrlClickEvents"]),
        'url_in_email': "EmailEvents",
        'basic_email': "EmailEvents",
        'email_and_address': "EmailEvents",
        'basic_domain': create_table_union(["DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents", "EmailEvents", "EmailUrlInfo"]),
        'basic_hostname': create_table_union(["DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents", "EmailEvents", "EmailUrlInfo"]),
        'basic_file': create_table_union(["DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents"]),
        'file_and_url': create_table_union(["DeviceEvents", "DeviceFileEvents"]),
        'file_and_origin_ip': create_table_union(["DeviceEvents", "DeviceFileEvents"]),
        'file_and_remote_ip': "DeviceEvents",
        'file_and_remote_url': "DeviceEvents",
        'file_ip_and_url': create_table_union(["DeviceEvents", "DeviceFileEvents"]),
        'file_and_process': create_table_union(["DeviceEvents", "DeviceFileEvents"]),
        'fileIP_and_FileUrl': create_table_union(["DeviceEvents", "DeviceFileEvents"]),
        'sigma2kql': [],
    }

    for key in queries:
        if key == 'basic_email' and len(objects['email_addrs']) > 0:
            condition = or_condition(["SenderMailFromAddress", "SenderFromAddress"], objects['email_addrs'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'email_and_address' and len(objects['email_addrs']) > 0 and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0):
            condition1 = or_condition(["SenderMailFromAddress", "SenderFromAddress"], objects['email_addrs'])
            condition2 = or_condition(["SenderIPv4", "SenderIPv6"], objects['v4_addrs'] + objects['v6_addrs'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'basic_ipv4' and len(objects['v4_addrs']) > 0:
            condition = or_condition(["FileOriginIP", "RemoteIP", "RequestSourceIP", "SenderIPv4"], objects['v4_addrs'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'basic_ipv6' and len(objects['v6_addrs']) > 0:
            condition = or_condition(["FileOriginIP", "RemoteIP", "RequestSourceIP", "SenderIPv6"], objects['v6_addrs'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'basic_url' and len(objects['urls']) > 0:
            condition = or_condition(["FileOriginUrl", "RemoteUrl", "FileOriginReferrerUrl", "Url"], objects['urls'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'basic_domain' and len(objects['domain_names']) > 0:
            condition = or_condition(["RemoteUrl", "RequestAccountDomain", "UrlDomain", "SenderFromDomain", "SenderMailFromDomain"], objects['domain_names'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'basic_hostname' and len(objects['hostnames']) > 0:
            condition = or_condition(["RemoteUrl", "RequestAccountDomain", "UrlDomain", "SenderFromDomain", "SenderMailFromDomain"], objects['hostnames'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'basic_file' and len(objects['hashes']) > 0:
            condition = hash_condition(["", "InitiatingProcess"], objects['hashes'])
            queries[key] += f"\n| where {condition}"
            continue

        if key == 'file_and_url' and len(objects['hashes']) > 0 and len(objects['urls']) > 0:
            condition1 = or_condition(["FileOriginUrl", "FileOriginReferrerUrl"], objects['urls'])
            condition2 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'file_and_origin_ip' and len(objects['hashes']) > 0 and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0):
            condition1 = or_condition(["FileOriginIP"], objects['v4_addrs'] + objects['v6_addrs'])
            condition2 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'file_and_remote_ip' and len(objects['hashes']) > 0 and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0):
            condition1 = or_condition(["RemoteIP"], objects['v4_addrs'] + objects['v6_addrs'])
            condition2 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'file_and_remote_url' and len(objects['hashes']) > 0 and len(objects['urls']) > 0:
            condition1 = or_condition(["RemoteUrl", ], objects['urls'] + objects['domain_names'])
            condition2 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'file_ip_and_url' and len(objects['hashes']) > 0 and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0) and len(objects['urls']) > 0:
            condition1 = or_condition(["FileOriginIP"], objects['v4_addrs'] + objects['v6_addrs'])
            condition2 = or_condition(["FileOriginUrl", "FileOriginReferrerUrl"], objects['urls'])
            condition3 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2}) and ({condition3})"
            continue

        if key == 'file_and_process' and len(objects['hashes']) > 0:
            condition1 = hash_condition(["InitiatingProcess"], objects['hashes'])
            condition2 = hash_condition([""], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'fileIP_and_FileUrl' and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0) and len(objects['urls']) > 0:
            condition1 = or_condition(["FileOriginIP"], objects['v4_addrs'] + objects['v6_addrs'])
            condition2 = or_condition(["FileOriginUrl", "FileOriginReferrerUrl"], objects['urls'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'url_in_email' and len(objects['urls']) > 0 and len(objects['email_addrs']) > 0:
            condition1 = or_condition(["SenderMailFromAddress", "SenderFromAddress"], objects['email_addrs'])
            condition2 = or_condition(["Url"], objects['urls'])
            queries[key] += f"\n| where {condition1}"
            queries[key] += f"\n| join kind=rightsemi EmailUrlInfo on NetworkMessageId"
            queries[key] += f"\n| where {condition2}"
            continue

        if key == 'ip_and_file' and (len(objects['v4_addrs']) > 0 or len(objects['v6_addrs']) > 0) and len(objects['hashes']) > 0:
            condition1 = or_condition(["RemoteIP"], objects['v4_addrs'] + objects['v6_addrs'])
            condition2 = hash_condition(["InitiatingProcess"], objects['hashes'])
            queries[key] += f"\n| where ({condition1}) and ({condition2})"
            continue

        if key == 'sigma2kql' and len(objects['sigma_rules']) > 0:
            for rule in objects['sigma_rules']:
                queries[key] += backend.translate(rule)
            continue

        queries[key] = ""

    return queries
