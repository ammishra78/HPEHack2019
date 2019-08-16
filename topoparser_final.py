import os
import json
import sys
from argparse import ArgumentParser
import re
import math
import topo_logical_array

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

    #grid[r_cent][c_cent] = dev_name

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
    name = list(dev_name)
    
    inds_to_replace = list(range(c_cent - sub,  c_cent + sub))
    print(inds_to_replace)
    for i, c in zip(inds_to_replace, name):
        grid[r_cent][i] = c
    
        
    print("center= ", r_cent, c_cent)
    print(sub)

    
    
    
    
#     
#     print(inds_to_delete)
# 
#     for i in sorted(inds_to_delete, reverse=True):
#         del grid[r_cent][i]
#         #grid[r_cent].remove("*")
# #     for i, j in zip(range(c_cent - sub, c_cent), range(c_cent + 1, c_cent + sub)):
# #         #del grid[r_cent][i]
# #         #del grid[r_cent][j]
# #         print("i = {} j= {}".format(i, j))
# #         grid[r_cent][i] = "*"
# #         grid[r_cent][j] = "*"

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
 
 
def draw_v_line(grid,coord,size):
    x,y = coord
    for i in range(x, x+size):
        grid[i][y] = "*"
    return grid
        
def draw_h_line(grid,coord,size):    
    x,y = coord
    for i in range(y, y+size):
        grid[x][i] = "*"  
    return grid  
    
def main(arguments):
    node_dict = create_node_dict()
    link_set = create_set_links()
    print("======================================")
    print(node_dict)
    print(link_set)
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
    logical_grid_width = 5
    logical_grid_length = 3
    logical_array = topo_logical_array.create_logical_array(array_width=logical_grid_width, array_length=logical_grid_length)
    
    # Dimensions of the grid
    num_rows = 12*logical_grid_length
    num_cols = 15*logical_grid_width
    
    # Dimensions for switch
    sw_width = 10
    sw_height = 5
    #sw_coord = (2, 2)
    
    if num_cols >= 80:
        print("WARNING: The line cannot exceed 80 characters. \
                Please adjust the variables to decrease the grid width.")
        
    
    # Dimensions for host
    hs_width = 1
    hs_height = 1
    #hs_coord = (2, 2)
    
    # Create any empty grid
    grid = create_empty_grid(num_rows, num_cols)
    print_grid(grid)
    dev_coord = {}
    
    for row_idx, row in enumerate(logical_array):
        for item_idx, item in enumerate(row):
            if item is not "o":
                #handle devices
                if item is not "|" and item is not "-":
                    dev_log_coord = topo_logical_array.search_dev_location(logical_array, item)
                    print(dev_log_coord)
                    dev_grid_coord = []
                    dev_grid_coord.insert(0, ((dev_log_coord[0]*(sw_height+2)) + 1))
                    dev_grid_coord.insert(1, ((dev_log_coord[1]*(sw_width+2)) + 1))
                    dev_coord[item] = dev_grid_coord
                    
                    grid = draw_device(grid, item, dev_grid_coord, sw_width, sw_height)
                    print_grid(grid)
                    
                """    
                #handle connections
                
                elif item == "|":
                    #add vertical line
                    line_log_coord = [row_idx, item_idx]
                    print("Line logical coord: {}".format(line_log_coord))
                    line_grid_coord = []
                    line_grid_coord.insert(0, ((line_log_coord[0]*(sw_height+2))+(sw_height//2 + 2)))
                    line_grid_coord.insert(1, ((line_log_coord[1]*(sw_width+2))+(sw_width//2 + 2)))
                    
                    #Call vertical line here
                    grid = draw_v_line(grid, line_grid_coord, (sw_height))
                    print_grid(grid)
                    
                elif item == "-":
                    #add horizontal line
                    line_log_coord = [row_idx, item_idx]
                    print("Line logical coord: {}".format(line_log_coord))
                    line_grid_coord = []
                    line_grid_coord.insert(0, ((line_log_coord[0]*(sw_height+2))+(sw_height//2 + 2)))
                    line_grid_coord.insert(1, ((line_log_coord[1]*(sw_width+2))))
                    
                    #Call horizontal line here
                    grid = draw_h_line(grid, line_grid_coord, (sw_width + 2))
                    print("After draw h line")
                    print_grid(grid)

                else:
                    print("Something went wrong in the array.")
                """ 
    #handle connections
    for connection in link_set:
        d1_coord = dev_coord[connection[0]]
        d2_coord = dev_coord[connection[1]]
        
        print(connection)
        print(d1_coord)
        print(d2_coord)
        
        highest_dv = min(d1_coord[0], d2_coord[0])
        lowest_dv = max(d1_coord[0], d2_coord[0])
        
        left_dv = min(d1_coord[1], d2_coord[1])
        right_dv = max(d1_coord[1], d2_coord[1])
        
        #dv1 higher and to the left of dv2
        if (d1_coord[0] < d2_coord[0]) and (d1_coord[1] < d2_coord[1]):
            #vertical line
            start_coord = ((d1_coord[0]+sw_height), (d1_coord[1]+(sw_width//2)))
            v_line_size = (sw_height//2) + 2
            grid = draw_v_line(grid, start_coord, v_line_size)
            
            #
            intersect_coord = ((d1_coord[0]+sw_height + (sw_height//2) + 2), (d1_coord[1]+(sw_width//2)))
            h_line_size = int((1.5*sw_width + 4))
            grid = draw_h_line(grid, intersect_coord, h_line_size)
            
            
            
        
        
        
        
    
    
    
    """
    grid_with_switch = draw_device(grid, "switch", sw_coord, sw_width, sw_height)
    print_grid(grid_with_switch)
    grid_with_switch_hs = draw_device(grid_with_switch, "hs1", hs_coord, hs_width, hs_height)        
    print_grid(grid_with_switch_hs)
    """

if __name__ == "__main__":
    main(sys.argv[1:])
    
    
    