#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import apifunctions
import cgi,cgitb

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
            print("session id : " + domain_sid + "<br>")

        get_domain_result =apifunctions.api_call(ip_addr, "show-domains", {}, domain_sid)
        
        if(debug == 1):
            print(json.dumps(get_domain_result))
            print("<br>")

        for x in range(get_domain_result['total']):
            #print(get_domain_result['objects'][x]['name'])
            domain_list.append(get_domain_result['objects'][x]['name'])

        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, domain_sid)
        if(debug == 1):
            print(logout_result)
            print("<br>")
    except:
        print("Unable to get Domain List<br>")
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
            print("session id : " + cma_sid + "<br>")
        
        check_host_obj = {"type" : "host", "filter" : ip_2_find, "ip-only" : "true"}
        check_host = apifunctions.api_call(ip_addr, "show-objects", check_host_obj, cma_sid)

        if(check_host['total'] == 0):
            print("no host exist<br>")
        else:
            #print(json.dumps(check_host))
            for x in range(check_host['total']):
                print(check_host['objects'][x]['name'])
                print("<br>")
                print(check_host['objects'][x]['ipv4-address'])
                print("<br>")
                whereused_by_name(check_host['objects'][x]['name'], ip_addr, cma, cma_sid)
        
        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        if(debug == 1):
            print(logout_result)
            print("<br>")
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain<br>")
#end of search_domain_4_ip

"""
login to domain and see if an object with name exist
"""
def search_domain_4_name(ip_addr, cma, name):
    debug = 0
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid + "<br>")

        check_name = {"order" : [{"ASC" : "name"}], "in" : ["name", name] }
        chkname = apifunctions.api_call(ip_addr, "show-objects", check_name, cma_sid)

        if(chkname['total'] == 0):
            print("No object found<br>")
        else:
            for x in range(chkname['total']):
                print(chkname['objects'][x]['name'])
                print("<br>")
                print(chkname['objects'][x]['type'])
                print("<br>")
                whereused_by_name(name, ip_addr, cma, cma_sid)
        
        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)

        if(debug == 1):
            print(logout_result)
            print("<br>")
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain<br>")
#end of search_domain_4_name

"""
search through a cma for a network.
"""
def search_domain_4_network(ip_addr, cma, network, netmask):
    debug = 0
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid + "<br>")
        
        check_network_obj = {"type" : "network", "filter" : network, "ip-only" : "true", "limit" : "50"}
        chknet = apifunctions.api_call(ip_addr, "show-objects", check_network_obj, cma_sid)

        if(chknet['total'] == 0):
            print("no network found in cma<br>")
        else:
            found = 0
            ##
            if(debug == 1):
                print("Looking For<br>")
                print(network)
                print("<br>")
                print(netmask)
                print("<br>")
                print("end looking for<br>")
                print(json.dumps(chknet))
                print("<br>")

            for i in range(chknet['total']):
                if(debug == 1):
                    print(chknet['objects'][i]['name'])
                    print("<br>")
                    print(chknet['objects'][i]['subnet4'])
                    print("<br>")
                    print(chknet['objects'][i]['subnet-mask'])
                    print("<br>")
                    print(chknet['objects'][i]['mask-length4'])
                    print("<br>")

                if(((chknet['objects'][i]['subnet4'] == network) and (str(chknet['objects'][i]['mask-length4']) == netmask)) or ((chknet['objects'][i]['subnet4'] == network) and (chknet['objects'][i]['subnet-mask'] == netmask))):
                    #good job ... we found it.
                    print("*****************************<br>")
                    print("network match at  <br>")
                    found = 1
                    print(chknet['objects'][i]['name'])
                    whereused_by_name(chknet['objects'][i]['name'], ip_addr, cma, cma_sid)
                    print("<br>^^^^^^^^^^^^^^^^^^^^^^^^^^^^^<br>")
             # end of for loop

            if(found == 0):
                 print("Nothing Found<br>")
        #end of else
            ##
        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)

        if(debug == 1):
            print(logout_result)
            print("<br>")
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain<br>")
#end of search_domain_4_network

"""
do a where used on the cma for a name
"""
def whereused_by_name(name, ip_addr, cma, sid):
    debug = 0

    print("Doing function Where Used<br>")
    search_where_json = {
        "name" : name
    }

    where_used_result = apifunctions.api_call(ip_addr, "where-used", search_where_json, sid)

    if(debug == 1):
        print("^^^^^^^^^^^^^^^^^^^^<br>")
        print(json.dumps(where_used_result))
        print("<br>")
        print("!!!!!!!!!!!!!!!!!!!!<br>")

    try:
        dtotal = where_used_result['used-directly']['total']
        print("Total Where Used Directly : <br>")
        print(dtotal)
        print("<br>")

        len_obj          = len(where_used_result['used-directly']['objects'])
        len_access_rule  = len(where_used_result['used-directly']['access-control-rules'])
        len_threat_prev  = len(where_used_result['used-directly']['threat-prevention-rules'])
        len_nat_rules    = len(where_used_result['used-directly']['nat-rules'])

        if(debug == 1):
            print(len_obj)
            print("<br>")
            print(len_access_rule)
            print("<br>")
            print(len_threat_prev)
            print("<br>")
            print(len_nat_rules)
            print("<br>")

        print("Use in Object :<br>")
        for x in range(len_obj):
            print("Use in " + where_used_result['used-directly']['objects'][x]['name'] + " which is a " + where_used_result['used-directly']['objects'][x]['type'])
            print("<br>")
            sub_search = where_used_result['used-directly']['objects'][x]['name']
            ### add on 07.30 
            print("################ Sub Search for " + sub_search + " ########################<br>")
            whereused_by_name(sub_search, ip_addr, cma, sid)

            #print(where_used_result['used-directly']['objects'][x]['name'])
            #print(where_used_result['used-directly']['objects'][x]['type'])

        print("Use in Access Rule:<br>")
        for x in range(len_access_rule):
            print("use in policy : " + where_used_result['used-directly']['access-control-rules'][x]['layer']['name'] + " rule-number " + where_used_result['used-directly']['access-control-rules'][x]['position'])
            print("<br>")

            tmp_uid = where_used_result['used-directly']['access-control-rules'][x]['rule']['uid']
            tmp_layer = where_used_result['used-directly']['access-control-rules'][x]['layer']['name']

            get_access_rule = {
                'uid' : tmp_uid,
                'layer' : tmp_layer
            }

            access_rule_result = apifunctions.api_call(ip_addr, 'show-access-rule', get_access_rule, sid)

            rule_output(access_rule_result)

            #print(where_used_result['used-directly']['access-control-rules'][x]['position'])
            #print(where_used_result['used-directly']['access-control-rules'][x]['layer']['name'])
        
        print("Use in Threat Prevention Rules:<br>")
        for x in range(len_threat_prev):
            print("feature not avaliable.  send greg what you searched for")
            print("<br>")
        
        print("Use in Nat Rules<br>")
        for x in range(len_nat_rules):
            print("use in nat rules | policy " + where_used_result['used-directly']['nat-rules'][x]['package']['name'] + " nat-rule number " + where_used_result['used-directly']['nat-rules'][x]['position'])
            print("<br>")
            #print(where_used_result['used-directly']['nat-rules'][x]['position'])
            #print(where_used_result['used-directly']['nat-rules'][x]['package']['name'])
    except:
        print("Not used or not searchable<br>")

    try:
        itotal = where_used_result['used-indirectly']['total']
        print("Total Where Used InDirectly : <br>")
        print(itotal)
        print("<br>")
    except:
        pass
#end of whereused_by_name()

"""
output of rule
"""
def rule_output(access_rule_result):
    out = "<br>"
    debug = 0

    print("Rule_Output", end=out)

    print("#####################", end=out)
    if(debug == 1):
        print(json.dumps(access_rule_result), end=out)
    
    s_len = len(access_rule_result['source'])
    d_len = len(access_rule_result['destination'])
    p_len = len(access_rule_result['service'])

    if(debug == 1):
        print(access_rule_result['source'], end=out)
        print("++", end=out)
        print(access_rule_result['destination'], end=out)
        print("++", end=out)
        print(access_rule_result['service'], end=out)
        print("++", end=out)
        print("#####################", end=out)
        #print(s_len) #+ "  " + d_len + "  " + p_len, end=out)

    print("SOURCE:", end=out)
    for x in range(s_len):
        #print(out)
        print(access_rule_result['source'][x]['name'], end=" : ")
        print(access_rule_result['source'][x]['type'], end=out)
        #print("______________________", end=out)
    
    print("DESTINATION:", end=out)
    for x in range(d_len):
        #print(out)
        print(access_rule_result['destination'][x]['name'], end=" : ")
        print(access_rule_result['destination'][x]['type'], end=out)
    
    print("PORTS:", end=out)
    for x in range(p_len):
        #print(out)
        print(access_rule_result['service'][x]['name'], end=out)
        #print(access_rule_result['service'][x]['type'], end=out)

    print("++++++++++++++++++++++", end=out)
#end of rule_output

def main():
    debug = 1
    
    #create instance of field storage
    form = cgi.FieldStorage()
    what_2_search_for = form.getvalue('searchfor')

    ## html header and config data dump
    print ("Content-type:text/html\r\n\r\n")
    print ("<html>")
    print ("<head>")
    print ("<title>Cross Domain Search Results</title>")
    print ("</head>")
    print ("<body>")
    print("X-Domain Search 0.1<br><br>")

    mds_ip = "192.168.159.150"

    
    print("Searching for a " + what_2_search_for)
    print("<br>")

    if(what_2_search_for == "ipaddress"):
        print(form.getvalue('ip2find'))
        print("<br>")
    elif(what_2_search_for == "name"):
        print(form.getvalue('name2find'))
        print("<br>")
    elif(what_2_search_for == "network"):
        print(form.getvalue('net2find'))
        print("<br>")
        print(form.getvalue('mask2find'))
        print("<br>")
    else:
        print("unknown selection")
    
        
    domain_list = get_domains(mds_ip)

    for x in domain_list:
        print("Searching CMA : " + x + "<br>")

        if(what_2_search_for == "ipaddress"):
            #print(form.getvalue('ip2find'))
            #print("<br>")
            search_domain_4_ip(mds_ip, x, form.getvalue('ip2find'))
            
        elif(what_2_search_for == "name"):
            #print(form.getvalue('name2find'))
            #print("<br>")
            search_domain_4_name(mds_ip, x, form.getvalue('name2find'))

        elif(what_2_search_for == "network"):
            #print(form.getvalue('net2find'))
            #print("<br>")
            #print(form.getvalue('mask2find'))
            #print("<br>")

            search_domain_4_network(mds_ip, x, form.getvalue('net2find'), form.getvalue('mask2find'))
        else:
            print("unknown selection")
        print("<br>^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^<br>")

    print("------- end of program -------")
    print("<br><br>")
    print("</body>")
    print("</html>")
#end of main()



if __name__ == "__main__":
    main()
#end of program