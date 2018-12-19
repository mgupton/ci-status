# ci-status

*ci-status* is a script that shows all child accounts for a specified Alert Logic account (cid) and for each account it enumerates all Cloud Insight Deployments. For each deployment a summary is provided, which includes the number of scannable hosts and the number of hosts scanned. In addition, the VPCs will be listed for any VPCs that do not have room for the /28 subnet needed by CI.

```
Usage:
    ci-status authenticate --username=<username> --password=<password>
    ci-status get-summary --auth-token=<auth_token> --cid=<cid>

Options:
    --cid=<cid>
    -u --username=<username>
    -p --password=<password>
    -a --auth-token=<auth_token>
    -f --format=<format>                json, text
```

## authenticate
Get an authentication token that can be used for other commands.
```
export auth_token=$(python ci-status.py -u $un -p $pw)
```

## get-summary

List all child accounts for the specified parent account (cid). For each child account list all Cloud Insight Deployments. For each Deployment list the total number of scannables hosts and the total number of hosts that have been scanned. Also list all VPCs that do not have room for the /28 subnet that CI needs for deploying the scanner instances.
```
python ci-status.py get-summary -a $auth_token --cid $cid | tee ci-status.txt
```

## Examples of script output
```
...

-----------------------------------------------
Account: Acme Systems, CID: 1335570
-----------------------------------------------
Deployment Name: Production
**There is no room for a subnet in these VPCs:
/aws/us-east-1/vpc/vpc-25035e41
/aws/us-east-1/vpc/vpc-1e035e7a
/aws/us-east-1/vpc/vpc-e6035e82
/aws/us-east-1/vpc/vpc-d069efb4
/aws/us-east-1/vpc/vpc-52920f34
Total number of hosts: 51
Number of hosts in scope: 46
Number of scannable hosts: 8
Number of hosts scanned: 8

...

-----------------------------------------------
Summary:
Total number of hosts: 6738
Total number of hosts in scope: 5335
Total number of scannable hosts: 4516
Total number of hosts scanned: 2765
Percentage of in scope hosts that are scanned: 51%
Percentage of scannable hosts that are scanned: 61%
Percentage of total hosts that are scanned: 41%
```