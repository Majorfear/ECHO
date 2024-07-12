# MIT License
# Copyright (c) 2024 Guido Hovens
# See the LICENSE file for more details.

import sys
import argparse
import configparser
from helpers import *
import kql_queries
import kibana_queries
from pycti import OpenCTIApiClient

# Variables
config = configparser.ConfigParser()
try:
    config.read('opencti.conf')
    api_url = config.get('OPENCTI', 'URL')
    api_token = config.get('OPENCTI', 'TOKEN')
except configparser.Error as e:
    print(f"Error reading configuration: {e}")
    sys.exit(1)

# OpenCTI initialization
opencti = OpenCTIApiClient(api_url, api_token, log_level='warning')

# Parse command line arguments
parser = argparse.ArgumentParser(description="Guido's amazing tool")
parser.add_argument('-c', '--count', type=int, help='Number of reports to process')
parser.add_argument('-r', '--report', help='Specific report ID to process')
parser.add_argument('-a', '--all', action='store_true', help='Process all reports, also those that have been processed already')
args = parser.parse_args()

if args.count:
    if args.report:
        print("Report and count are mutually exclusive.")
        sys.exit(0)
    try:
        count = int(args.count)
        if count < 1:
            print("Count must be at least 1.")
            sys.exit(0)
    except ValueError:
        print("Count must be a positive integer and at least 1.")
        sys.exit(0)


def create_objects(report):
    """
    Creates a dictionary of objects from a report.

    Args:
        report (dict): A report from OpenCTI.

    Returns:
        dict: A dictionary of objects.
    """
    objects = {
        'urls': [],
        'hashes': [],
        'v4_addrs': [],
        'v6_addrs': [],
        'hostnames': [],
        'email_addrs': [],
        'domain_names': [],
        'yara_rules': [],
        'sigma_rules': [],
    }

    # Mapping entity types to corresponding object keys
    entity_type_to_key = {
        "Domain-Name": 'domain_names',
        "Url": 'urls',
        "IPv4-Addr": 'v4_addrs',
        "IPv6-Addr": 'v6_addrs',
        "Hostname": 'hostnames',
        "Email-Addr": 'email_addrs'
    }

    for obj in report['objects']:
        entity_type = obj.get("entity_type")
        if entity_type in entity_type_to_key:
            objects[entity_type_to_key[entity_type]].append(obj['observable_value'])
        elif entity_type == "StixFile":
            observable = opencti.stix_cyber_observable.read(id=obj["id"])
            if observable and "hashes" in observable:
                objects['hashes'].extend(observable["hashes"])
        elif entity_type == "Indicator":
            id = obj.get("id")
            indicator = opencti.indicator.read(id=id)
            if indicator['pattern_type'] == "yara":
                objects['yara_rules'].append(indicator['pattern'])
            if indicator['pattern_type'] == "sigma":
                objects['sigma_rules'].append(indicator['pattern'])

    return objects


def patterns_to_notes(objects, report_id, labels):
    """
    Creates a note for each pattern in the objects dictionary.

    Args:
        objects (dict): A dictionary where keys are entity types
            (e.g., 'domain_names', 'urls') and values are the corresponding values.
    """
    abs = report_id + " Yara rule"
    
    for rule in objects['yara_rules']:
        opencti.note.create(
            abstract=abs,
            content="Rule:\n\n    " + rule.replace("\n", "\n    "),
            objects=[report_id],
            objectLabel=[labels['yara']]
        )
    abs = report_id + " Sigma rule"
    for rule in objects['sigma_rules']:
        opencti.note.create(
            abstract=abs,
            content="Rule:\n\n    " + rule.replace("\n", "\n    "),
            objects=[report_id],
            objectLabel=[labels['sigma']]
        )


def queries2notes(queries, report_id, label_id):
    """
    Creates a note for each query in the queries dictionary.

    Args:
        queries (dict): A dictionary where keys are query identifiers
            (e.g., 'basic_ipv4', 'basic_email') and values are the corresponding
            KQL query strings.
        report_id (str): The ID of the report.
        type (str, optional): The type of query. Defaults to "typeless".
    """
    query_to_abstract = {}
    query_to_abstract.update(kql_queries.query_to_abstract)
    query_to_abstract.update(kibana_queries.query_to_abstract)
    for name in queries.keys():
        abs = report_id + query_to_abstract[name]

        if len(queries[name]) < 2 or note_exists(abs, opencti):
            continue
        if name == "sigma2kql":
            for q in queries[name]:
                opencti.note.create(
                    abstract=abs,
                    content="Query:\n\n    " + q.replace("\n", "\n    "),
                    objects=[report_id],
                    objectLabel=[label_id]
                )
            continue
        opencti.note.create(
            abstract=abs,
            content="Query:\n\n    " + queries[name].replace("\n", "\n    "),
            objects=[report_id],
            objectLabel=[label_id]
        )


def process_report(report_id, labels):
    """
    Processes a report.

    Args:
        report_id (str): The ID of the report.
        labels (dict): A dictionary where keys are label names
            (e.g., 'processed','sigma', 'yara', 'kusto', 'kibana') and values
            are the corresponding OpenCTI label IDs.

    Returns:
        int: 0 if report was processed, 1 if report was not processed.
    """
    report = opencti.report.read(id=report_id)
    opencti.stix_domain_object.add_label(id=report["id"], label_id=labels['processed'])  # Mark report as processed.
    objects = create_objects(report)  # Create objects dictionary.
    if dict_empty(objects):
        return 1
    patterns_to_notes(objects, report["id"], labels)  # Create notes for each pattern.
    queries = kql_queries.create_queries(objects)
    queries2notes(queries, report["id"], labels['kusto'])  # Create notes for each query.
    queries = kibana_queries.create_queries(objects)
    queries2notes(queries, report["id"], labels['kibana'])  # Create notes for each query.


def main():
    # OpenCTI labels to be used.
    labels = {
        'processed': opencti.label.read_or_create_unchecked(value="pipeline_processed")["id"],
        'sigma': opencti.label.read_or_create_unchecked(value="Sigma")["id"],
        'yara': opencti.label.read_or_create_unchecked(value="Yara")["id"],
        'kusto': opencti.label.read_or_create_unchecked(value="Kusto")["id"],
        'kibana': opencti.label.read_or_create_unchecked(value="Kibana")["id"]
    }

    # Filter to get reports that have not been processed yet.
    filters={
            "mode": "and",
            "filters": [{"key": "objectLabel", "values": [labels['processed']], "operator":"not_eq"}],
            "filterGroups": [],
        }

    # Get all reports, if a specific report ID is not provided.
    if not args.report:
        print("Loading reports...")
        reports = opencti.report.list(
            customAttributes="id",
            first=args.count or 100,  # 100 when getting all reports (OpenCTI API definition).
            getAll=not args.count,  # True when getting all reports.
            orderBy="created_at",
            orderMode="desc",
            filters=filters if not args.all else None  # Get all reports when -a is used.
        )
        print("Done!")

        if len(reports) == 0:
            print("No reports to process. Exiting.")
            sys.exit(0)

        # Process the reports.
        printProgressBar(0, len(reports), prefix = 'Starting ...', suffix = 'Complete', length = 50)
        for idx, report in enumerate(reports):
            printProgressBar(idx + 1, len(reports), prefix = report["id"], suffix = 'Complete', length = 50)
            process_report(report["id"], labels)

    # Specific report ID provided.
    else:
        result = process_report(args.report, labels)
        if result == 1:
            print("Nothing to do. Exiting.")
        else:
            print("Done!")


if __name__ == "__main__":
    main()