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

borrowed from functions in my api lib ... since i need the json not just a true false
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
login to domain and see if host object with IP exist
"""
def search_domain_4_ip(ip_addr, cma, ip_2_find):
    debug = 0
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
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain")
#end of search_domain_4_ip

"""
login to domain and see if an object with name exist
"""
def search_domain_4_name(ip_addr, cma, name):
    debug = 0
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid)

        check_name = {"order" : [{"ASC" : "name"}], "in" : ["name", name] }
        chkname = apifunctions.api_call(ip_addr, "show-objects", check_name, cma_sid)

        if(chkname['total'] == 0):
            print("No object found")
        else:
            for x in range(chkname['total']):
                print(chkname['objects'][x]['name'])
                print(chkname['objects'][x]['type'])
        
        time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)

        if(debug == 1):
            print(logout_result)
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain")
#end of search_domain_4_name

"""
search through a cma for a network.
"""
def search_domain_4_network(ip_addr, cma, network, netmask):
    debug = 0
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid)
        
        check_network_obj = {"type" : "network", "filter" : network, "ip-only" : "true", "limit" : "50"}
        chknet = apifunctions.api_call(ip_addr, "show-objects", check_network_obj, cma_sid)

        if(chknet['total'] == 0):
            print("no network found in cma")
        else:
            found = 0
            ##
            if(debug == 1):
                print("Looking For")
                print(network)
                print(netmask)
                print("end looking for")
                print(json.dumps(chknet))

            for i in range(chknet['total']):
                if(debug == 1):
                    print(chknet['objects'][i]['name'])
                    print(chknet['objects'][i]['subnet4'])
                    print(chknet['objects'][i]['subnet-mask'])
                    print(chknet['objects'][i]['mask-length4'])

                if(((chknet['objects'][i]['subnet4'] == network) and (str(chknet['objects'][i]['mask-length4']) == netmask)) or ((chknet['objects'][i]['subnet4'] == network) and (chknet['objects'][i]['subnet-mask'] == netmask))):
                    #good job ... we found it.
                    print("*****************************")
                    print("network match at  ")
                    found = 1
                    print(chknet['objects'][i]['name'])
                    print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
             # end of for loop

            if(found == 0):
                 print("Nothing Found")
        #end of else
            ##
        time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)

        if(debug == 1):
            print(logout_result)
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain")
#end of search_domain_4_network

def main():
    print("X-Domain Search 0.1")

    mds_ip = "146.18.96.16"
    search4 = "146.18.2.137"

    domain_list = get_domains(mds_ip)

    print(domain_list)
    for x in domain_list:
        print("Searching CMA : " + x)
        #search_domain_4_ip(mds_ip, x, search4)
        #search_domain_4_name(mds_ip, x, "loki.infosec.fedex.com")
        search_domain_4_network(mds_ip, x, "146.18.0.0", "255.255.0.0")
        print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        search_domain_4_network(mds_ip, x, "155.161.0.0", "16")
        print("=======================================")

if __name__ == "__main__":
    main()
#end of program