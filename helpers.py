# MIT License
# Copyright (c) 2024 Guido Hovens
# See the LICENSE file for more details.

def dict_empty(objects):
    """
    Checks if a dictionary is empty.
    """
    return all(len(lst) == 0 for lst in objects.values())


def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)	
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    if iteration == total:
        print()


def note_exists(name, opencti):
    """
    Checks if an OpenCTI note exists.
    """	
    note = opencti.note.read(
        filters={
            "mode": "and",
            "filters": [{"key": "attribute_abstract", "values": [name]}],
            "filterGroups": [],
        }
    )

    return True if note else False


def list_to_kql(list):
    """
    Converts a list to a KQL string.
    """	
    if len(list) == 0:
        return "\"\""
    return str(list).replace("'", '"')[1:-1]


def processed(report, label_id):
    """
    Checks if a report has a label.
    """
    for label in report['objectLabel']:
        if label["id"] == label_id:
            return True
    return False