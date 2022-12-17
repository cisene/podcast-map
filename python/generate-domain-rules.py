#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import mysql.connector
import re
import time
import random

import warnings
warnings.filterwarnings("error")

import yaml

import argparse

from collections import OrderedDict

import idna

global conn
global cur

global contents

YAML_BASE = './yaml/'
YAML_TLDS = YAML_BASE + 'tlds/'

YAML_EXCLUDE_DOMAINS = YAML_BASE + 'domains-exclude.yaml'
YAML_EXCLUDE_TLDS = YAML_BASE + 'tlds-exclude.yaml'


RE_PROTO = r"^http(s)?\x3a\x2f\x2f"

MISSED_FRACTIONS_URLS = './work/url-fractions.txt'
MISSED_FULL_URLS = './work/url-full.txt'

URL_LOG_FULLURL = './work/missed-url-full.txt'
URL_LOG_FRACTIONURL = './work/missed-url-fragments.txt'


def writeLogFullURL(feedlink):
  # Force all links to be https -- simplify
  feedlink = re.sub(r"^http(s)?\x3a\x2f\x2f", "https://", str(feedlink), flags=re.IGNORECASE)

  with open(URL_LOG_FULLURL, "a") as f:
    f.write(feedlink + "\n")

def writeLogFragmentURL(feedlink):
  if re.search(r"^http(s)?\x3a\x2f\x2f", str(feedlink), flags=re.IGNORECASE):
    feedlink = re.sub(r"^http(s)?\x3a\x2f\x2f([a-z0-9\x2d\x2e\x5f]{1,})", "", str(feedlink), flags=re.IGNORECASE)
    feedlink = str(feedlink).lower()

  with open(URL_LOG_FRACTIONURL, "a") as f:
    f.write(feedlink + "\n")

  return

def sliceURL(feedlink):
  if re.search(r"^http(s)?\x3a\x2f\x2f", str(feedlink), flags=re.IGNORECASE):
    feedlink = re.sub(r"^http(s)?\x3a\x2f\x2f([a-z0-9\x2d\x2e\x5f]{1,})", "", str(feedlink), flags=re.IGNORECASE)
    feedlink = str(feedlink).lower()
  return feedlink


def regexify(data):
  contents = data

  contents = re.sub(r"\x2c", r"\\x2c", str(contents), flags=re.IGNORECASE)
  contents = re.sub(r"\x2d", r"\\x2d", str(contents), flags=re.IGNORECASE)

  contents = re.sub(r"\x2e", r"\\x2e", str(contents), flags=re.IGNORECASE)
  contents = re.sub(r"\x2f", r"\\x2f", str(contents), flags=re.IGNORECASE)


  return contents

def fulltrim(data):
  data = re.sub(r"^\s{1,}", "", str(data), flags=re.IGNORECASE)
  data = re.sub(r"\s{1,}$", "", str(data), flags=re.IGNORECASE)
  data = re.sub(r"\s{2,}", " ", str(data), flags=re.IGNORECASE)

  data = re.sub(r"\x2520$", "", str(data), flags=re.IGNORECASE)
  data = re.sub(r"\x2522$", "", str(data), flags=re.IGNORECASE)

  return data

def debrisRemover(data):
  data = re.sub(r"\x3fdoing\x5fwp\x5fcron\x3d(\d{1,})\x2e(\d{1,})$", "", str(data), flags=re.IGNORECASE)
  data = re.sub(r"\x23\x5f\x3d\x5f$", "", str(data), flags=re.IGNORECASE)

  return data


def flipDomain(domain):
  elem = re.split(r"\x2e", domain)
  elem.reverse()
  return ".".join(elem)

def safeSQL(data):
  #global conn
  data = re.sub(r"\x5c$", "", data)
  data = re.sub(r"(\x5c)?\x5c\x27", "''", data)
  data = re.sub(r"\x5c\x27", "'", data)
  data = re.sub(r"\x27", "''", data)
  data = re.sub(r"\x5c{1,}", "", data) # anything any amount of backslash to double backslash
  data = re.sub(r"\s{2,}", " ", data)
  data = data.lstrip().rstrip()
  
  return data


def disconnectMySQL():
  global conn
  global cur

  cur = None
  conn = None


def connectMySQL(db_host, db_port, db_database, db_username, db_password):
  global conn
  global cur

  conn = None
  while True:
    try:
      conn = mysql.connector.connect(
        user=db_username,
        password=db_password,
        host=db_host,
        database=db_database,
        charset='utf8',
        use_unicode=True,
        auth_plugin='mysql_native_password'
      )
      break


    except mysql.connector.errors.OperationalError:
      print("MySQL connection attempt failed, waiting ...")
      time.sleep(5)
      pass

    except mysql.connector.errors.DatabaseError as e:
      print("MySQL Database Error: '{0}'".format(str(e)))
      time.sleep(5)
      pass

    except mysql.connector.errors.InterfaceError as e:
      print("MySQL Database Error: '{0}'".format(str(e)))
      time.sleep(5)
      pass

    finally:
      if conn != None:
        break

  cur = conn.cursor(buffered=True)
  
  cur.execute('SET NAMES utf8mb4')
  cur.execute("SET CHARACTER SET utf8mb4")
  cur.execute("SET character_set_connection=utf8mb4")


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


def writeYAML(contents, fullpath):
  s = yaml.safe_dump(
    contents,
    indent=2,
    width=1000,
    canonical=False,
    sort_keys=False,
    explicit_start=False,
    default_flow_style=False,
    default_style='',
    allow_unicode=True,
    line_break='\n'
  )

  s = re.sub(r"\n\x2d\s{1}", "\n\n- ", str(s), flags=re.IGNORECASE)
  with open(fullpath, "w") as f:
    f.write(s)


def getTopLevelDomain(data):
  elems = []
  tld = None

  if data != None:
    if isinstance(data, str) == True:
      if re.search(r"\x2e", str(data), flags=re.IGNORECASE):
        try:
          elems = re.split(r"\x2e", str(data), flags=re.IGNORECASE)
          tld = elems[0]
        finally:
          pass
    else:
      print(str(data))
      exit(0)

  return tld


def unpuny(data):
  result = None
  if re.search(r"^xn\x2d\x2d", str(data), flags=re.IGNORECASE):
    # We have encountered punycode
    result = idna.decode(data)
  else:
    result = data
  return result


def deChunkDomains(domains):

  tld_keys = domains['rulesets'].keys()

  sort_tlds = []
  for k in tld_keys:
    sort_tlds.append(k)

  sort_tlds.sort()

  for tld in sort_tlds:
    domain = domains['rulesets'][tld]
    # print(domain)

    fullpath = './yaml/tld-' + str(tld) + '.yaml'
    content = { 'rulesets': [] }
    content['rulesets'] = domain

    writeYAML(content, fullpath)


def getDomainsAboveLimit(exclude_domains_dict):
  contents = {}
  contents['domains'] = {}

  ex = []
  for edd in exclude_domains_dict['exclude']:
    obj = "'" + str(edd) + "'"
    if obj not in ex:
      ex.append(str(obj))
  ex_list = ",".join(ex)

  domain_count = 0

  print(f"Database query for a total list of domains ...")
  #query = "SELECT channel_domain FROM podmix.channels WHERE channel_domain != '' AND channel_deleted = 0 GROUP BY channel_domain HAVING COUNT(*) >= 2;"

  #query = "SELECT channel_domain FROM podmix.channels WHERE channel_domain != '' AND channel_domain NOT IN (" + ex_list + ") AND channel_deleted = 0 GROUP BY channel_domain HAVING COUNT(*) >= 2;"
  query = "SELECT channel_domain FROM podmix.channels WHERE channel_domain != '' AND channel_domain NOT IN (" + ex_list + ") AND channel_deleted = 0 GROUP BY channel_domain HAVING COUNT(*) >= 2;"
  #print(query)

  cur.execute(query)
  for (channel_domain) in cur:

    if channel_domain != None:

      channel_domain = channel_domain[0]

      # Skip over IP addresses
      if re.search(r"^(\d{1,3})\x2e(\d{1,3})\x2e(\d{1,3})\x2e(\d{1,3})$", str(channel_domain), flags=re.IGNORECASE):
        continue

      # Skip over domains that do not contain a dot/period
      if not re.search(r"\x2e", str(channel_domain), flags=re.IGNORECASE):
        continue

      # Skip over domain that contain UNDERSCORES -- Not normal
      if re.search(r"\x5f", str(channel_domain), flags=re.IGNORECASE):
        continue

      if re.search(r"^xn\x2d\x2d", str(channel_domain), flags=re.IGNORECASE):
        channel_domain_unpuny = unpuny(channel_domain)

        if channel_domain_unpuny != None:
          channel_domain = channel_domain_unpuny
        else:
          print(f"unpuny() mangled domain")

      tld = getTopLevelDomain(channel_domain)

      if tld == None:
        print(f"getTopLevelDomain() returned NULL for {channel_domain}")
        continue

      if tld != None:

        if tld not in contents['domains']:
          contents['domains'][tld] = []

        if channel_domain not in contents['domains'][tld]:
          contents['domains'][tld].append(channel_domain)
          domain_count += 1

  print(f".. returned {domain_count} domains.")
  return contents


def getFeedLinksForTLD(tld_domain):
  contents = []

  #query = "SELECT channel_feed_link FROM podmix.channels WHERE channel_deleted = 0 AND channel_domain = '" + str(safeSQL(tld_domain)) + "' ORDER BY RAND() ASC LIMIT 10000;"
  query = "SELECT channel_feed_link FROM podmix.channels WHERE channel_deleted = 0 AND channel_domain = '" + str(safeSQL(tld_domain)) + "' ORDER BY RAND() ASC LIMIT 1000;"
  cur.execute(query)
  for (channel_feed_link) in cur:
    if (isinstance(channel_feed_link, tuple) == True):
      channel_feed_link = channel_feed_link[0]

    if channel_feed_link not in contents:
      contents.append(channel_feed_link)

  contents.sort()
  return contents


def getRuleFileFromTLD(tld):
  result = YAML_TLDS + 'tld-' + str(tld).lower() + '.yaml'
  return result


def removeQueryString(link):
  return re.sub(r"\x3f(.*)$", "", str(link), flags=re.IGNORECASE)


def buildREfromFeedLink(feedlink, url_match_domain, common_endings):
  result = None
  contents = []

  contents.append(RE_PROTO)
  contents.append(r"([a-z0-9\x2d\x2e\x5f]{1,})?" + regexify(str(url_match_domain)))

  re_domain = "".join(contents)

  test_count = 0
  for re_pattern in common_endings['endings']:
    hit_count = 0
    test_count += 1
    re_domain_pattern = re_domain + re_pattern
    re_domain_full_pattern = re_domain_pattern + re_pattern

    try:
      if re.search(r"" + re_domain_pattern + "", str(feedlink), flags=re.IGNORECASE):
        result = re_domain_pattern
        hit_count += 1
        break

    except:
      print(f"Broken: {re_domain_full_pattern}")
      print(f"Partial: {re_pattern}")
      pass
      #exit(0)

    finally:
      pass

    if hit_count != 0:
      break

  if test_count != len(common_endings['endings']):
    pass
  
  return result



def processDomains(domains, exclude_domains):
  result = None
  common_endings = readYAML(YAML_BASE + 'urls-common-endings.yaml')

  missed_urls = []

  skip_tlds = []

  skip_domains = []

  miss_count = 0

  for edd in exclude_domains['exclude']:
    if edd not in skip_domains:
      skip_domains.append(edd)

  for tld in domains['domains']:

    if tld == None:
      continue

    if tld != "org":
     #  continue
     pass

    print(f"Processing TLD '{tld}' ..")
    if tld in skip_tlds:
      print(f"\t.. skipping '{tld}'")
      continue


    rulefile = getRuleFileFromTLD(tld)
    rules = readYAML(rulefile)
    #print(f"\tRead {rulefile} ..")


    yaml_update = False

    if rules == None:
      rules = {}
      rules['rulesets'] = {}

    for tld_domain in domains['domains'][tld]:
      miss_count = 0

      if tld_domain == None:
        continue

      if tld_domain in skip_domains:
        print(f"\t.. skipping {tld_domain} ..")
        continue

      url_match_domain = flipDomain(tld_domain)
      re_url_match_domain = regexify(url_match_domain + '/')

      feedlinks = getFeedLinksForTLD(tld_domain)

      for feedlink in feedlinks:
        feedlink = fulltrim(feedlink)

        #feedlink = debrisRemover(feedlink)
        
        if feedlink == None:
          continue

        if (
          re.search(r"webarchive\x2elibrary\x2eunt\x2eedu", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"cybercemetery\x2eunt\x2eedu", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"accounts\x2egoogle\x2ecom", str(feedlink), flags=re.IGNORECASE)
        ):
          continue

        if(
          re.search(r"\x2fv3\x2fsignin\x2fidentifier", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2fwp\x2dsignup\x2ephp", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2flogin(\x2ephp|\x3f)?", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2f\x3fpassword\x2dprotected\x3d", str(feedlink), flags=re.IGNORECASE) or
          re.search(f"\x2f404(\x2e(htm(l)?|php|as(h|p|m)(x)?|cfm|shtml))?$", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2f(\d{3})page\x2e", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2fbuy\x2ddomain\x2f", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2ffavicon\x2e", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2f(\d{3})error\x2ephp", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2fgdpr\x2dpolicy", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2flogin\x2f", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2ferror\x2f(\d{3})", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2f\x3ferror\x3d", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2fwp\x2dlogin\x2ephp", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2fcgi\x2dsys\x2fsuspendedpage\x2ecgi", str(feedlink), flags=re.IGNORECASE) or
          re.search(r"\x2f404", str(feedlink), flags=re.IGNORECASE)
        ):
          continue


        skip_feed = False
        #for re_skip in skip_list:
        #  if re.search(re_skip, str(feedlink), flags=re.IGNORECASE):
        #    skip_feed = True

        if skip_feed == True:
          continue

        if re.search(re_url_match_domain, str(feedlink), flags=re.IGNORECASE):

          if tld_domain not in rules['rulesets']:
            rules['rulesets'][tld_domain] = {}
            rules['rulesets'][tld_domain]['matching'] = []

          match_count = 0
          for match_rule in rules['rulesets'][tld_domain]['matching']:
            if match_rule == None:
              continue

            try:
              if re.search(r"" + match_rule + "", str(feedlink), flags=re.IGNORECASE):
                match_count += 1
                break

            except FutureWarning as e:
              print(f"error: {e}")
              print(f"feedlink: {feedlink}")
              print(f"match_rule: {match_rule}")
              pass

            except:
              print("Exception")
              pass

            finally:
              pass

          if match_rule == 0:
            if re.search(r"^http(s)?\x3a\x2f\x2ffeed(s)?\x2e", str(feedlink), flags=re.IGNORECASE):
              pass

          if match_count == 0:
            re_pattern = buildREfromFeedLink(str(feedlink), url_match_domain, common_endings)

            if re_pattern != None:
              if re_pattern not in rules['rulesets'][tld_domain]['matching']:
                rules['rulesets'][tld_domain]['matching'].append(re_pattern)
                yaml_update = True
                #print(f"\tProcessing '{tld_domain}'")
                #print(f"\t\t\t{feedlink}")
                #print(f"\t\t\t.. found pattern '{re_pattern}'. Adding to collection.\n")
            else:
              miss_count += 1
              feedlink = re.sub(r"^http\x3a\x2f\x2f", "https://", str(feedlink), flags=re.IGNORECASE)

              if feedlink not in missed_urls:
                missed_urls.append(feedlink)
                writeLogFullURL(feedlink)
                if sliceURL(feedlink) != "/":
                  writeLogFragmentURL(feedlink)

      # Cleanup
      if tld_domain in rules['rulesets']:
        matching_length = len(rules['rulesets'][tld_domain]['matching'])
        if matching_length == 0:
          domain_popped = rules['rulesets'].pop(tld_domain)
          yaml_update = True
          #print(f"\t.. popped domain {tld_domain} ..")

    if yaml_update == True:
      writeYAMLSorted(rules, rulefile)

  return missed_urls


def enrichDomains(domains, exclude_domains):
  files = []

  skip_domains = []

  for edd in exclude_domains['exclude']:
    if edd not in skip_domains:
      skip_domains.append(edd)

  for filename in os.listdir(YAML_TLDS):
    if str(filename) not in files:
      files.append(str(filename))

  files.sort()

  for filename in files:
    tld = re.sub(r"^tld\x2d(.+?)\x2eyaml$", "\\1", str(filename), flags=re.IGNORECASE)

    f = os.path.join(YAML_TLDS, filename)
    if os.path.isfile(f):
      rules = readYAML(f)

      for tld_domain in rules['rulesets']:

        if tld_domain in skip_domains:
          continue

        if str(tld) not in domains['domains']:
          domains['domains'][str(tld)] = []
          #print(f"Added missing TLD {tld}")

        if str(tld_domain) not in domains['domains'][tld]:
          domains['domains'][str(tld)].append(str(tld_domain))
        else:
          pass

    if tld in domains['domains']:
      if str(tld) in domains['domains']:
        domains['domains'][str(tld)].sort()



  return domains


def processMissedURLs(missed_urls):
  result = []

  machine_name = os.uname().nodename

  if machine_name != 'm3800':
    return

  for url in missed_urls:
    if re.search(r"^http(s)?\x3a\x2f\x2f", str(url), flags=re.IGNORECASE):
      work_url = url

      # Strip off protocol and domain
      work_url = re.sub(r"^http(s)?\x3a\x2f\x2f([a-z0-9\x2d\x2e\x5f]{1,})", "", str(work_url), flags=re.IGNORECASE)
      work_url = str(work_url).lower()

      if re.search(r"^\x2f$", str(work_url), flags=re.IGNORECASE):
        continue

      if work_url not in result:
        result.append(work_url)


  result.sort()
  #for r in result:
  #  print(r)

  s = "\n".join(result)

  with open(MISSED_FRACTIONS_URLS, "w") as f:
    f.write(s)

  with open(MISSED_FULL_URLS, "w") as f:
    f.write("\n".join(missed_urls))



def writeYAMLSorted(our_dict, rulefile):
  od = {}
  if "rulesets" not in od:
    od['rulesets'] = {}

  sorted_keys = sorted(our_dict['rulesets'].keys(), reverse=False)

  for key in sorted_keys:

    if key == None:
      continue

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

def truncateFile(path):
  if os.path.exists(path):
    os.remove(path)
    print(f"Removing temporary file {path} ..")


def init_argparse() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    usage="%(prog)s --db-host [OPTION] --db-user [OPTION] --db-password [OPTION]  --db-database [OPTION] ...",
    description="Export OPML based on definitions."
  )

  parser.add_argument(
    "--db-host", action='store', dest='db_host'
  )

  parser.add_argument(
    "--db-user", action='store', dest='db_user'
  )

  parser.add_argument(
    "--db-password", action='store', dest='db_password'
  )

  parser.add_argument(
    "--db-database", action='store', dest='db_database'
  )

  return parser


def main() -> None:

  parser = init_argparse()
  args = parser.parse_args()

  if(
    (args.db_host) and
    (args.db_user) and
    (args.db_password) and
    (args.db_database)
  ):
    print(f"host     : {args.db_host}")
    print(f"user     : {args.db_user}")
    print(f"password : {args.db_password}")
    print(f"database : {args.db_database}")

    connectMySQL(args.db_host, '3306', args.db_database, args.db_user, args.db_password)

  exclude_domains = readYAML(YAML_EXCLUDE_DOMAINS)

  # Get all domains that has more than two links in db
  domains = getDomainsAboveLimit(exclude_domains)
  writeYAML(domains, YAML_BASE + 'masterlist.yaml')


  domains = readYAML(YAML_BASE + 'masterlist.yaml')
  missed_urls = processDomains(domains, exclude_domains)

  if len(missed_urls) > 0:
    processMissedURLs(missed_urls)

  # Post-process, add missing domains that wasn't included from database
  domains = readYAML(YAML_BASE + 'masterlist.yaml')
  domains = enrichDomains(domains, exclude_domains)
  writeYAML(domains, YAML_BASE + 'masterlist.yaml')


  disconnectMySQL()



if __name__ == '__main__':
  main()
