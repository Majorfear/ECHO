# MIT License
# Copyright (c) 2024 Guido Hovens
# See the LICENSE file for more details.

import ipaddress
from helpers import dict_empty


query_to_abstract = {
    'DNS_ip_and_domain': " DNS with IP and Domain name Query",
    'DNS_domain': " DNS Domain name Query",
    'DNS_ip': " DNS IP Query",
    'ECS_DNS_ip_and_domain': " ECS DNS with IP and Domain name Query",
    'ECS_DNS_domain': " ECS DNS Domain name Query",
    'ECS_DNS_ip': " ECS DNS IP Query",
    'basic_url': " Url Only Query",
    'basic_ip': " IP Only Query",
    'basic_hash': " Hash Only Query",
    'basic_email': " Email Address Only Query",
}

def or_condition(fields, values):
    values_str = " or ".join(values)
    return " or ".join([f"{field}: ({values_str})" for field in fields])


def hash_condition(fields, values):
    """
    Creates an or condition of all hashes in values that have the given algorithm.

    Args:
        fields (list): A list of field names.
        values (list): A list of file hashes. For example [{algorithm: 'MD5', hash: '1234567890abcdef'}]
        algorithm (str): The hash algorithm.
    """
    filters = []
    algorithms = list({hash_dict['algorithm'] for hash_dict in values})
    for algorithm in algorithms:
        hashes = [hash_dict["hash"] for hash_dict in values if hash_dict['algorithm'] == algorithm]
        filters.append(or_condition([field + algorithm.replace("-", "") for field in fields], hashes))
    return " or ".join(filters)


def string_to_hex(s):
    """
    Converts a string to a hex string.

    Args:
        s (str): The string to convert.

    Returns:
        str: The hex string.
    """
    return ''.join(format(ord(c), '02x') for c in s)


def format_ip_addresses(v4_addrs, v6_addrs):
    """
    Converts a list of IP addresses to a list of hex strings.

    Args:
        v4_addrs (list): A list of IPv4 addresses.

    Returns:
        list: A list of hex strings.
    """
    addrs = [f'{ipaddress.IPv4Address(addr):x}' for addr in v4_addrs]
    addrs.extend(addr.replace(':', '') for addr in v6_addrs)
    return addrs


def format_domain_names(domain_names, hostnames):
    """
    Converts a list of domain names and hostnames to a list of hex strings.

    Args:
        domain_names (list): A list of domain names.

    Returns:
        list: A list of hex strings.
    """
    names = domain_names + hostnames
    return [string_to_hex(name) for name in names]


def create_queries(objects):
    """
    Generates Kibana Query Language (KQL) queries from the given objects.

    Args:
        objects: A list of objects
    
    Returns:
        dict: A dictionary where keys are query identifiers (e.g., 'basic_ipv4', 'basic_email') and values 
              are the corresponding KQL query strings.
    """
    if dict_empty(objects):
        return

    index = "(_index: soc-windows-* or _index: soc-linux-*)"
    queries = {
        'DNS_ip_and_domain': "",
        'DNS_domain': "",
        'DNS_ip': "",
        'ECS_DNS_ip_and_domain': "",
        'ECS_DNS_domain': "",
        'ECS_DNS_ip': "",
        'basic_url': "",
        'basic_ip': "",
        'basic_hash': "",
        'basic_email': "",
    }

    v4_addrs = objects.get('v4_addrs', [])
    v6_addrs = objects.get('v6_addrs', [])
    domain_names = objects.get('domain_names', [])
    hostnames = objects.get('hostnames', [])

    addrs = format_ip_addresses(v4_addrs, v6_addrs)
    names = format_domain_names(domain_names, hostnames)

    if addrs and names:
        queries['DNS_ip_and_domain'] = f"{index} and ({or_condition(['response.rrs.rdata'], addrs + names)})"
    elif addrs:
        queries['DNS_ip'] = f"{index} and ({or_condition(['response.rrs.rdata'], addrs)})"
    elif names:
        queries['DNS_domain'] = f"{index} and ({or_condition(['response.rrs.rdata'], names)})"
    
    if objects['urls']:
        queries['basic_url'] = f"{index} and ({or_condition(['url.original', 'url.domain'], objects['urls'])})"
    
    if objects['v4_addrs'] or objects['v6_addrs']:
        queries['basic_ip'] = f"{index} and ({or_condition(['destination.ip', 'source.ip'], objects['v4_addrs'] + objects['v6_addrs'])})"
        queries['ECS_DNS_ip'] = f"{index} and ({or_condition(['dns.resolved_ip'], objects['v4_addrs'] + objects['v6_addrs'])})"
    
    if objects['domain_names'] or objects['hostnames']:
        queries['ECS_DNS_domain'] = f"{index} and ({or_condition(['dns.question.registered_domain', 'dns.question.name', 'dns.answers.name'], objects['domain_names'] + objects['hostnames'])})"
        if len(queries['ECS_DNS_ip']) > 0:
            queries['ECS_DNS_ip_and_domain'] = f"{index} and ({or_condition(['dns.question.registered_domain', 'dns.question.name', 'dns.answers.name'], objects['domain_names'] + objects['hostnames'])}) and ({or_condition(['dns.resolved_ip'], objects['v4_addrs'] + objects['v6_addrs'])})"

    if objects['hashes']:
        queries['basic_hash'] = f"{index} and ({hash_condition(['hash.',], objects['hashes'])})"

    if objects['email_addrs']:
        queries['basic_email'] = f"{index} and ({or_condition(['email.cc.address', 'email.bcc.address', 'email.from.address', 'email.reply_to.address', 'email.sender.address', 'email.to.address'], objects['email_addrs'])})"

    return queries
