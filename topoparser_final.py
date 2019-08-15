import os
import json
import sys
from argparse import ArgumentParser
import re
import math

def parse_topo_string_from_file(file_contents):
    topology_re = r'(?P<TOPO>TOPOLOGY\s=\s\"\"\"\n.*?target=\"true\".*?\n\s*\"\"\"\n?)'
    re_result = re.search(topology_re, test_contents, flags=(DOTALL | IGNORECASE)).group(0)
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
	
	
def main(arguments):
    test_script = None
    arg_parser = ArgumentParser(description="Parse contents of test .py files")
    arg_parser.add_argument("test_script", action="store", type=test_script,
                            help=("The test script to be parsed"))
    arg_parser.add_argument("--format", action="store", type=output_format,
                            default="json", dest="output_format",
                            help=("Format for output to be dumped"))
    args = arg_parser.parse_args(args=arguments)
    test_script = args.test_script
    out_fmt = args.output_format
    abs_path = os.path.abspath(test_script).split('/')
    keyword = 'halon-test' if 'halon-test' in abs_path else 'halon-src'
    rel_path = '/'.join(abs_path[abs_path.index(keyword):])

    with open(test_script, 'r') as file_pointer:
        test_contents = file_pointer.read()
		topo_string = parse_topo_string_from_file(test_contents)
	
	""" Code to parse Topology string goes here"""
	# Dimensions of the grid
	\num_rows = 20
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
	print(grid)
	grid_with_switch = draw_switch(grid, "switch", sw_coord, sw_width, sw_height)
	print(grid_with_switch)
	grid_with_switch_hs = draw_switch(grid_with_switch_hs, "hs1", hs_coord, hs_width, hs_height)		
	print(grid_with_switch_hs)
