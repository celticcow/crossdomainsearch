#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import apifunctions

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Greg_Dunlap / CelticCow

cross domain search functions for Checkpoint
"""

"""
on mds side:
mgmt_cli -r true  show domains --format json
 .total for num of domains
 jq '.objects[] | .name'
"""
def get_domains(ip_addr):
    domain_list = []
    debug = 0
    try:
        domain_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, "")
        if(debug == 1):
            print("session id : " + domain_sid)

        get_domain_result =apifunctions.api_call(ip_addr, "show-domains", {}, domain_sid)
        
        if(debug == 1):
            print(json.dumps(get_domain_result))

        for x in range(get_domain_result['total']):
            #print(get_domain_result['objects'][x]['name'])
            domain_list.append(get_domain_result['objects'][x]['name'])

        time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, domain_sid)
        if(debug == 1):
            print(logout_result)
    except:
        print("Unable to get Domain List")
    return(domain_list)
#end of get_domains

"""
"""
def search_domain_4_ip(ip_addr, cma, ip_2_find):
    debug = 1
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid)
        
        check_host_obj = {"type" : "host", "filter" : ip_2_find, "ip-only" : "true"}
        check_host = apifunctions.api_call(ip_addr, "show-objects", check_host_obj, cma_sid)

        if(check_host['total'] == 0):
            print("no host exist")
        else:
            #print(json.dumps(check_host))
            for x in range(check_host['total']):
                print(check_host['objects'][x]['name'])
                print(check_host['objects'][x]['ipv4-address'])
        
        time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        if(debug == 1):
            print(logout_result)
    except:
        print("can't get into domain")
#end of search_domain_4_ip


def main():
    print("X-Domain Search 0.1")

    mds_ip = "146.18.96.16"
    search4 = "146.18.2.137"

    domain_list = get_domains(mds_ip)

    print(domain_list)
    for x in domain_list:
        print(x)
        search_domain_4_ip(mds_ip, x, search4)
        print("=======================================")

if __name__ == "__main__":
    main()
#end of program