import os
import json
import sys
from argparse import ArgumentParser
import re
import math

def parse_topo_string_from_file(test_contents):
    topology_re = r'(?P<TOPO>TOPOLOGY\s=\s\"\"\"\n.*?target=\"true\".*?\n\s*\"\"\"\n?)'
    re_result = re.search(topology_re, test_contents, flags=(re.DOTALL | re.IGNORECASE)).group(0)
    return re_result

def create_empty_grid(num_rows, num_cols):
    grid = []
    for i in range(num_rows):
        temp = []
        for j in range(num_cols):
            temp.append(' ')
        grid.append(temp)
    return grid


def draw_device(grid, dev_name, coord, dev_width, dev_height):
    row, col = coord

    r_cent = row + (dev_height // 2)
    c_cent = col + (dev_width // 2)

    grid[r_cent][c_cent] = dev_name

    grid[row][col] = '+'
    grid[row + dev_height][col] = '+'
    grid[row][col + dev_width] = '+'
    grid[row + dev_height][col + dev_width] = '+'
    # Draw top horizontal line
    for i in range(col + 1, col + dev_width):
        grid[row][i] = '-'
    # Draw bottom horizontal line
    for i in range(col + 1, col + dev_width):
        grid[row + dev_height][i] = '-'

    # Draw left vertical line
    for i in range(row + 1, row + dev_height):
        grid[i][col] = '|'

    # Draw right vertical line
    for i in range(row + 1, row + dev_height):
        grid[i][col + dev_width] = '|'

    xtra = len(dev_name)
    sub = math.ceil(xtra / 2)

    print("center= ", r_cent, c_cent)
    print(sub)

    temp = grid[r_cent]
    for i, j in zip(range(c_cent - sub, c_cent), range(c_cent + 1, c_cent + sub)):
        del grid[r_cent][i]
        del grid[r_cent][j]

    return grid

def print_grid(grid):
    print('\n'.join([''.join(l) for l in grid]))
    
    
def create_set_links(): 
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
    
    print("The link set: {}".format(link_set))
    return(link_set)
    
    #print(links_list)  #dictionary
    
def create_node_dict():
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
    
    
def main(arguments):
    test_script = None
    test_script = "test_ft_VxLAN_TrafficMultiAVPNVP.py"
    """"
    arg_parser = ArgumentParser(description="Parse contents of test .py files")
    arg_parser.add_argument("test_script", action="store", type=test_script,
                            help=("The test script to be parsed"))
    arg_parser.add_argument("--format", action="store", 
                            default="json", dest="output_format",
                            help=("Format for output to be dumped"))
    args = arg_parser.parse_args(args=arguments)
    test_script = args.test_script
    out_fmt = args.output_format
    abs_path = os.path.abspath(test_script).split('/')
    keyword = 'halon-test' if 'halon-test' in abs_path else 'halon-src'
    rel_path = '/'.join(abs_path[abs_path.index(keyword):])
    """
    with open(test_script, 'r') as file_pointer:
        test_contents = file_pointer.read()
    topo_string = parse_topo_string_from_file(test_contents)
    print(topo_string)
    
    """ Code to parse Topology string goes here"""
    # Dimensions of the grid
    num_rows = 20
    num_cols = 20
    
    # Dimensions for switch
    sw_width = 10
    sw_height = 5
    sw_coord = (2, 2)
    
    # Dimensions for host
    hs_width = 1
    hs_height = 1
    hs_coord = (2, 2)
    
    # Create any empty grid
    grid = create_empty_grid(num_rows, num_cols)
    print_grid(grid)
    grid_with_switch = draw_device(grid, "switch", sw_coord, sw_width, sw_height)
    print_grid(grid_with_switch)
    grid_with_switch_hs = draw_device(grid_with_switch, "hs1", hs_coord, hs_width, hs_height)        
    print_grid(grid_with_switch_hs)

if __name__ == "__main__":
    main(sys.argv[1:])