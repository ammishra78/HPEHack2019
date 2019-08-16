'''
Created on Aug 15, 2019
@author: beltracr
'''

'''
"TOPOLOGY": "TOPOLOGY = \"\"\"\n\n# Nodes\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops1\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops2\n[type=host name=\"Host 1\"] hs1\n[type=host name=\"Host 1\"] hs2\n\n# Links\nhs1:eth1 -- ops1:if01\nops1:if02 -- ops2:if02\nops2:if01 -- hs2:eth1\n\"\"\"\n",
'''

"""
# Nodes
[type=halon_0 name="OpenSwitch 1" target="true"] ops1
[type=host name="Host 1" image="ubuntuscapy_2.4:latest"] hs1
[type=host name="Host 2" image="ubuntuscapy_2.4:latest"] hs2
[type=host name="Host 3" image="ubuntuscapy_2.4:latest"] hs3


# Links
ops1:if01 -- hs1:eth1
ops1:if02 -- hs2:eth1
ops1:if03 -- hs3:eth1
"""
def create_set_links(topo_string=""): 
    links_list = {}
    topo_string = "TOPOLOGY = \"\"\"\n\n# Nodes\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops1\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops2\n[type=host name=\"Host 1\"] hs1\n[type=host name=\"Host 1\"] hs2\n\n# Links\nhs1:eth1 -- ops1:if01\nops1:if02 -- ops2:if02\nops2:if01 -- hs2:eth1\n\"\"\"\n"
    text_strip = topo_string.strip()
    #print(text_strip)

    str1, str2, str3 = text_strip.split("# ")
    #print(str2)
    
    link_set = set()
    
    for item in str2.splitlines():
        if "Switch" in item:
            switch_label = item.split(" ")[-1]
            #print(switch_label)              

    for item3 in str3.splitlines():
        if "--" in item3:
            spl = item3.split(" ")[0].split(":")[0]
            spl3 = item3.split(" ")[2].split(":")[0]
            links_list[spl] = [spl3] 
            tup_test = (spl,spl3)
            #print(tup_test)
            link_set.add(tup_test)
    
    print("The set of links: {}".format(link_set))
    return(link_set)
    
    #print(links_list)  #dictionary
    
def create_node_dict(topo_string=""):
    topo_string = "TOPOLOGY = \"\"\"\n\n# Nodes\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops1\n[type=halon_0 name=\"OpenSwitch 1\" target=\"true\"] ops2\n[type=host name=\"Host 1\"] hs1\n[type=host name=\"Host 1\"] hs2\n\n# Links\nhs1:eth1 -- ops1:if01\nops1:if02 -- ops2:if02\nops2:if01 -- hs2:eth1\n\"\"\"\n"
     
    link_dict = {}
    node_dict = {}
     
    strSplit = topo_string.strip()
    #print(strSplit)
    strSplit0, strSplit1, strSplit2 = strSplit.split("# ")
    node_list = strSplit1.splitlines()
    #print("node list = ",node_list)
    
    link_list = strSplit2.splitlines()
    #print("link list = ",link_list)
    #print("\n\n")
     
    for item in link_list:
        if "--" in item:
            dev = item.split(" ")[0].split(":")[0]
            dev2 = item.split(" ")[-1].split(":")[0]
            link_dict[dev] = [dev2]
              
    #print(link_dict)

    for item in node_list:
        if ("Node" not in item) and (item != ''):
            node = item.split(" ")[-1]
            node_dict[node] = []
            for key in link_dict.keys():
                if node == key:
                    #print(node, str(link_dict[key]).split("'")[1])
                    node_dict[node].append(str(link_dict[key]).split("'")[1])
                if node == str(link_dict[key]).split("'")[1]:
                    #print(node, key)
                    node_dict[node].append(key)
                     
    print("The node dict: {}".format(node_dict))
    return node_dict
"""
create_set_links()
print("\n=================================================================================\n")
create_node_dict()
"""