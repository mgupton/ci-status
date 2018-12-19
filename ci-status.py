"""
ci-status is a CLI tool for showing information about what is being scanned by
Cloud Insight and what is not. In addition, it will identify the reasons hosts
are not being scanned. For example, if there is no scope selected for an environment.

Usage:
    ci-status authenticate --username=<username> --password=<password>
    ci-status get-summary --auth-token=<auth_token> --cid=<cid>

Options:
    --cid=<cid>
    -u --username=<username>
    -p --password=<password>
    -a --auth-token=<auth_token>
    -f --format=<format>                json, text

"""

from docopt import docopt
import json
import requests
from requests.auth import HTTPBasicAuth
import enum
import CIStatus
from time import sleep

API_BASE_URL = "https://api.cloudinsight.alertlogic.com"

def main():

    args = docopt(__doc__)

    if args["authenticate"]:
        token = authenticate(args["--username"], args["--password"])
        print(token)
    elif args["get-summary"]:
        cids = get_child_cids(args["--auth-token"], args["--cid"])
        accounts = get_account_details(args["--auth-token"], cids)
        summary = get_accounts_summary(accounts)
        print_account_details_fmt(accounts, summary)
    
def authenticate(username, password):
    global API_BASE_URL

    api_endpoint = API_BASE_URL + "/aims/v1/authenticate"

    try:
        r = requests.post(api_endpoint, auth=HTTPBasicAuth(username, password))
    except Exception as e:
        print(e)

    if r.status_code == 200:
        pass

    r = json.loads(r.text)

    print(r["authentication"]["token"])

    return None

def get_child_cids(auth_token, cid):
    global API_BASE_URL

    api_url = API_BASE_URL + "/aims/v1/%s/account_ids/managed?active=true" % (cid)

    headers = {"Accept": "application/json", "x-aims-auth-token": "%s" % (auth_token)}

    r = requests.get(api_url, headers=headers)

    cids = json.loads(r.text)

    cids = cids["account_ids"]

    cids.insert(0, cid) 

    return cids

def get_account_details(auth_token, cids):
    global API_BASE_URL

    headers = {"Accept": "application/json", "x-aims-auth-token": "%s" % (auth_token)}

    accounts = {}

    for cid in cids:
        api_url = API_BASE_URL + "/aims/v1/%s/account" % (cid)

        r = requests.get(api_url, headers=headers)

        acct_details = json.loads(r.text)

        environments = get_ci_environment_details(auth_token, cid)
        tasklist = get_strawboss_notifications(auth_token, cid)

        acct_details["ci_environments"] = environments
        acct_details["tasklist"] = tasklist

        accounts[acct_details["id"]] = acct_details

        sleep(2)

    return accounts

def get_accounts_summary(accounts):
    
    summary = {'total': 0, 'in_scope': 0, 'scannable': 0, 'scanned': 0}

    for account in accounts.values():
 
        environments = account["ci_environments"]

        for environment in environments:
            summary["total"] += environment["summary"]["total"]
            summary["in_scope"] += environment["summary"]["in_scope"]
            summary["scannable"] += environment["summary"]["scannable"]
            summary["scanned"] += environment["summary"]["scanned"]

    return summary

def print_account_details(accounts):
    print(json.dumps(accounts))

def print_account_details_fmt(accounts, summary):
    for account in accounts.values():
        print("\n-----------------------------------------------")
        print("Account: %s, CID: %s" % (account["name"], account["id"]))

        environments = account["ci_environments"]

        if len(environments) == 0:
            print("**No deployments are configured for this account.")

        for environment in environments:
            print("-----------------------------------------------")
            print("Deployment Name: %s" % (environment["name"]))

            vpcs = cidr_check(account["tasklist"], environment["id"])

            if vpcs:
                print("**There is no room for a subnet in these VPCs:")

                for vpc in vpcs:
                    print("%s" % vpc)

            print("Total number of hosts: %s" % (environment["summary"]["total"]))
            print("Number of hosts in scope: %s" % (environment["summary"]["in_scope"]))
            print("Number of scannable hosts: %s" % (environment["summary"]["scannable"]))
            print("Number of hosts scanned: %s" % (environment["summary"]["scanned"]))

    print("\n\n\n-----------------------------------------------")
    print("Summary:")
    print("Total number of hosts: %s" % (summary["total"]))
    print("Total number of hosts in scope: %s" % (summary["in_scope"]))
    print("Total number of scannable hosts: %s" % (summary["scannable"]))
    print("Total number of hosts scanned: %s" % (summary["scanned"]))

    in_scope_percentage = int(float(summary["scanned"]) / float(summary["in_scope"]) * 100)
    scannable_percentage = int(float(summary["scanned"] / float(summary["scannable"])) * 100)
    total_percentage = int(float(summary["scanned"]) / float(summary["total"]) * 100)

    print("Percentage of in scope hosts that are scanned: %s%%" % (in_scope_percentage))
    print("Percentage of scannable hosts that are scanned: %s%%" % (scannable_percentage))
    print("Percentage of total hosts that are scanned: %s%%" % (total_percentage))

def print_account_summary(accounts):
    pass

def get_ci_environment_details(auth_token, cid):
    global API_BASE_URL

    headers = {"Accept": "application/json", "x-aims-auth-token": "%s" % (auth_token)}

    api_url = API_BASE_URL + "/environments/v1/%s?defender_support=false" % (cid)

    r = requests.get(api_url, headers=headers)

    environments = []
    environments_buf = json.loads(r.text)

    for env in environments_buf["environments"]:
        env_buf = {}

        summary = get_scan_summary_details(auth_token, cid, env["id"])

        env_buf["name"] = env["name"]
        env_buf["id"] = env["id"]
        env_buf["summary"] = summary

        environments.append(env_buf)

    return environments

def get_scan_summary_details(auth_token, cid, env_id):
    global API_BASE_URL

    headers = {"Accept": "application/json", "x-aims-auth-token": "%s" % (auth_token)}

    api_url = API_BASE_URL + "/scheduler/v1/%s/%s/summary" % (cid, env_id)

    r = requests.get(api_url, headers=headers)

    summary = json.loads(r.text)

    return summary["summary"]

def get_strawboss_notifications(auth_token, cid):
    global API_BASE_URL

    headers = {"Accept": "application/json", "x-aims-auth-token": "%s" % (auth_token)}

    api_url = API_BASE_URL + "/strawboss/v1/%s/tasklist" % (cid)

    r = requests.get(api_url, headers=headers)

    tasklist = json.loads(r.text)

    if len(tasklist["tasklist"]) == 0:
        tasklist = None
    else:
        tasklist = tasklist["tasklist"]
    
    return tasklist

def cidr_check(tasklist, envid):
    
    vpcs = []

    if tasklist == None:
        return None

    for task in tasklist:
        if task["task_id"] == "no_available_cidr_ranges" and task["environment_id"] == envid:
            vpcs.append(task["vpc_key"])

    if len(vpcs) == 0:
        vpcs = None
        
    return vpcs

class OutputType(enum.Enum):
    JSON = 1
    TEXT = 2

if __name__ == "__main__":
    main()