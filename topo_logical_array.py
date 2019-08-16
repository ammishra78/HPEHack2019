#draw the ascii topo map
import parse_test


def print_array(array):
    for i in range(0, len(array)):
        print(array[i])
        
def search_dev_location(array, device_name):
    idx1 = None
    idx2 = None
    for sublist in array:
        if device_name in sublist:
            idx2 = sublist.index(device_name)
            idx1 = array.index(sublist)
            break
    
    if idx1 == None or idx2 == None:
        print("Error finding devices in the array.")
        return(idx1, idx2) 
    else:
        return(idx1, idx2)
             

def most_connected_device(set_of_links):
    #create flat list
    link_list = [item for tup in set_of_links for item in tup] 
    most_common = max(set(link_list), key = link_list.count)
    print("The most connected device is: {}".format(most_common))
    return(most_common)
           

def create_logical_array(array_width=5, array_length=3):
    
    array_width_center = array_width//2
    array_length_center = array_length//2
    
    topo_log_array = []
    for i in range(0, array_length):
        topo_log_array.append([])
        for k in range(0, array_width):
            topo_log_array[i].append("o")    
    
    
    set_of_links = parse_test.create_set_links()
    dvc_connects = parse_test.create_node_dict()
    #only 1 most connected device
    most_connected_dvc = most_connected_device(set_of_links)
    # up to 4 least connected devices
    least_connected_dvcs = list(dvc_connects.keys())
    least_connected_dvcs.remove(most_connected_dvc)
    
    #place most_connected device in the center
    topo_log_array[array_length_center][array_width_center] = most_connected_dvc
    
    #place least connected devices in the corners
    for device in least_connected_dvcs:
        if topo_log_array[0][0] == "o":
            topo_log_array[0][0] = device
        elif topo_log_array[0][array_width-1] == "o":
            topo_log_array[0][array_width-1] = device
        elif topo_log_array[array_length-1][0] == "o":
            topo_log_array[array_length-1][0] = device
        elif topo_log_array[array_length-1][array_width-1] == "o":
            topo_log_array[array_length-1][array_width-1] = device
    """        
    print("Set Corners")
    print_array(topo_log_array)
    """
    
    
    #create connections between devices
    for link_tuple in set_of_links:
        first_dev_name = link_tuple[0]  #update with data in link
        first_dev_loc = search_dev_location(topo_log_array, first_dev_name)
        
        second_dev_name = link_tuple[1]  #update with data in link
        second_dev_loc = search_dev_location(topo_log_array, second_dev_name)
        
        
        #add vertical links
        if first_dev_loc[0] != second_dev_loc[0]:
            higher_row = min(first_dev_loc[0], second_dev_loc[0])
            lower_row = max(first_dev_loc[0], second_dev_loc[0])
            
            #final link will be added to index [row of second_dev -1][col of first_dev]
            for row_idx in range(higher_row, lower_row):
                if topo_log_array[row_idx][first_dev_loc[1]] == "o":
                    topo_log_array[row_idx][first_dev_loc[1]] = "|"
            
        #add horizontal links    
        if first_dev_loc[1] != second_dev_loc[1]:
            right_col = max(first_dev_loc[1], second_dev_loc[1])
            left_col = min(first_dev_loc[1], second_dev_loc[1])
            #print("Devices: {} - {}".format(first_dev_loc, second_dev_loc))
            #final link will be added to index [row of second_dev -1][col of first_dev]
            for col_idx in range(left_col, right_col):
                
                if topo_log_array[second_dev_loc[0]][col_idx] == "o":
                    topo_log_array[second_dev_loc[0]][col_idx] = "-"
        
        
    print("\nLogical Array:")
    print_array(topo_log_array)
    
    return(topo_log_array)



create_logical_array()