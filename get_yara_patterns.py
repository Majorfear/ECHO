# MIT License
# Copyright (c) 2024 Guido Hovens
# See the LICENSE file for more details.

import sys
import configparser
from pycti import OpenCTIApiClient

config = configparser.ConfigParser()
config.read('opencti.conf')
api_url = config.get('OPENCTI','URL')
api_token = config.get('OPENCTI','TOKEN')

# OpenCTI initialization
opencti = OpenCTIApiClient(api_url, api_token, log_level='warning')

if not len(sys.argv) == 2:
    sys.exit(0)

report = opencti.report.read(id=sys.argv[1])

for obj in report['objects']:
    entity_type = obj.get("entity_type")
    if entity_type == "Indicator":
        id = obj.get("id")
        indicator = opencti.indicator.read(id=id)
        if indicator['pattern_type'] == "yara":
           print(indicator['pattern'] + "\n") 
