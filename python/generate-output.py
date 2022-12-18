#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import random

import yaml
from collections import OrderedDict

import json

import idna

import xml.etree.ElementTree as ET

from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from xml.dom import minidom

from datetime import datetime

global conn
global cur

global contents

YAML_BASE = '../yaml/'
YAML_TLDS = YAML_BASE + 'tlds/'


XML_BASE = '../xml/'
XML_RULES = XML_BASE + "podcast-url-formats.xml"


JSON_BASE = '../json/'
JSON_RULES = JSON_BASE + "podcast-url-formats.json"


def GenerateTimestamp():
  result = None
  my_date = datetime.now()
  result = my_date.isoformat()

  result = re.sub(r"T", "-rev-", str(result), flags=re.IGNORECASE)
  result = re.sub(r"\x3a", "", str(result), flags=re.IGNORECASE)
  result = re.sub(r"\x2e(\d{1,})$", "", str(result), flags=re.IGNORECASE)
  return result


def readYAML(filepath):
  contents = None
  yaml_contents = None
  if os.path.isfile(filepath):
    fp = None
    try:
      fp = open(filepath)
      yaml_contents = fp.read()
      fp.close()

    finally:
      pass

  if yaml_contents != None:
    contents = yaml.safe_load(yaml_contents)

  return contents

def writeXML(contents, fullpath):
  with open(fullpath, "w") as f:
    f.write(contents)

  return

def writeJSON(contents, fullpath):
  with open(fullpath, "w") as f:
    f.write(contents)
  return

def getRuleFileFromTLD(tld):
  result = YAML_TLDS + 'tld-' + str(tld).lower() + '.yaml'
  return result


def renderXMLMap(domain_dict):
  result = None
  count_tlds = 0
  count_domains = 0
  count_rules = 0

  datetimestamp = GenerateTimestamp()

  jsonbuffer = {}
  jsonbuffer['@meta'] = {}
  jsonbuffer['rulesets'] = {}
  
  elems = []

  # Element 0
  elems.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
  
  # Element 1
  elems.append("<!-- Author: Christopher Isene christopher.isene@gmail.com -->\n")
  jsonbuffer['@meta']['author'] = "Christopher Isene christopher.isene@gmail.com"

  # Element 2
  elems.append("<!-- Source: https://github.com/cisene/podcast-map/podcast-url-formats.xml -->\n")
  jsonbuffer['@meta']['source'] = "https://github.com/cisene/podcast-map/podcast-url-formats.json"

  # Element 3
  elems.append("<!-- Top Level Domains: 0 -->\n")

  # Element 4
  elems.append("<!-- Domains: 0 -->\n")

  # Element 5
  elems.append("<!-- Rules: 0 -->\n")

  # Element 6
  elems.append("<!-- Revision: 1970-01-01 00:00:00 -->\n")

  # Element 7
  elems.append("<rulesets>\n")

  for domain_tld in domain_dict['domains']:
    domain_rules_file = getRuleFileFromTLD(domain_tld)
    domain_rules = readYAML(domain_rules_file)

    if domain_rules == None:
      print(f"Were not able to load rulesets for {domain_tld} ..")
      continue

    elems.append(f"  <ruletld tld=\"{domain_tld}\">\n")

    if domain_tld not in jsonbuffer['rulesets']:
      jsonbuffer['rulesets'][domain_tld] = {}
    
    count_tlds += 1

    #print(f"Processing {domain_tld} ..")
    for domain in domain_rules['rulesets']:

      elems.append(f"    <ruleset domain=\"{domain}\">\n")
      count_domains += 1

      if domain not in jsonbuffer['rulesets'][domain_tld]:
        jsonbuffer['rulesets'][domain_tld][domain] = {}
        jsonbuffer['rulesets'][domain_tld][domain]['matching'] = []

      for matching in domain_rules['rulesets'][domain]['matching']:
        elems.append(f"      <matching>{matching}</matching>\n")
        count_rules += 1

        jsonbuffer['rulesets'][domain_tld][domain]['matching'].append(str(matching))

      elems.append("    </ruleset>\n")
    elems.append("  </ruletld>\n")
  elems.append("</rulesets>\n")
      
  elems[3] = f"<!-- Top Level Domains: {count_tlds} -->\n"
  jsonbuffer['@meta']['TopLevelDomains'] = int(count_tlds)

  elems[4] = f"<!-- Domains: {count_domains} -->\n"
  jsonbuffer['@meta']['Domains'] = int(count_domains)

  elems[5] = f"<!-- Rules: {count_rules} -->\n"
  jsonbuffer['@meta']['Rules'] = int(count_rules)

  elems[6] = f"<!-- Revision: {datetimestamp} -->\n"
  jsonbuffer['@meta']['Revision'] = str(datetimestamp)

  xml_contents = "".join(elems)
  writeXML(xml_contents, XML_RULES)

  json_contents = json.dumps(jsonbuffer, indent=2, sort_keys=False)
  writeJSON(json_contents, JSON_RULES)
  return

def writeYAMLSorted(our_dict, rulefile):
  od = {}
  if "rulesets" not in od:
    od['rulesets'] = {}

  sorted_keys = sorted(our_dict['rulesets'].keys(), reverse=False)

  for key in sorted_keys:
    if key not in od['rulesets']:
      od['rulesets'][key] = {}

    if "matching" not in od['rulesets'][key]:
      od['rulesets'][key]['matching'] = []

    matching = our_dict['rulesets'][key]['matching']
    matching.sort()

    od['rulesets'][key]['matching'] = matching

  writeYAML(od, rulefile)
  print(f"\tWrote {rulefile} .. ")
  return


def main():

  domains = readYAML(YAML_BASE + 'masterlist.yaml')
  renderXMLMap(domains)



if __name__ == '__main__':
  main()
