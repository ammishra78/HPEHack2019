# (c) Copyright 2019 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# The contents of this software are proprietary and confidential
# to the Hewlett Packard Enterprise Development LP. No part of this
# program may be photocopied, reproduced, or translated into another
# programming language without prior written consent of the
# Hewlett Packard Enterprise Development LP.
from retrying import retry
from topology_common.utils.threading import ThreadGroup
from time import sleep
from pytest import (
    mark,
    fixture
)
from topology_common.ops.vxlan.ft_vxlan_lib import (
    TrafficType,
    verify_mac_table
)

from topology_common.ops.vlans.vlan import configure_switch_vlan

from topology_common.ops.l3_common.ft_l3_lib import (
    AddressType
)

from fixtures import (
    env_setup_hs_sw_hs_hs_hs,
    l2_basic_phy,
    l3_basic_phy
)

__doc__ = """
Test Case Header:
=================
:Author: Anvita Mishra anvita.mishra@hpe.com
:TestId: 00000
:Release: 10_04
:TestName: test_ft_VxLAN_TrafficMultiAVPNVP
:Objective: Verify VXLAN encapsulation and decapsulation across
            multiple AVPs and NVPs with multiple traffic types.
            The NVPs are part of a multi-member ECMP group.
:Requirements:
    - 1 switch
    - 4 hosts
:TestDescription: This test-case verifies VXLAN encapsulation is working for
    different traffic types on AVP-->All direction and decapsulation for
    NVP-->All direction. This test-case also verifies ECMP load balancing
    behavior for Known Unicast Traffic

    1.  Setup the topology as shown and enable all interfaces.
    2.  Configure VXLAN on the switch
    3.  Send packet from AVP1 to all other hosts. Verify correct
        encapsulation at one NVP (one member of the ECMP group)
        and correct packet transmission at AVP2.
    4.  Send encapsulated packet from NVP1 to all and verify that
        the packet is correctly decapsulated at AVP1 for known unicast traffic
        and flooded to all AVPs for all other traffic types. Verify that the
        packet is not received at the NVP on the same tunnel.
    5.  Testing ECMP Load Balancing behavior by permuting the Source MAC
        bitwise and checking which member of the ECMP group receives traffic.
:PlanPriority: 3 - High
:TestPassCriteria: -
    1. Setup of the topology successfully created.
    2. Packet successfully transmitted from AVP1 to all other hosts.
    3. Source MAC from packet sucessfully learned
    4. Packet successfully transmitted from NVP1 to all other hosts.
    5. Source MAC from packet successfully learned.
    6. Packet Permutations successfully transmitted from AVP1 to all other hosts.
    7. ECMP Load Balancing behavior occurs as expected for each traffic type
:PlatformIndependent: Y
:SupportedPlatforms: 8325
Topology:
=========
.. ditaa::

+-----------+   +-----------+
|           |   |           |
|   h3      |   |   h4      |
|   NVP1    |   |   NVP2    |
|           |   |           |
+----+------+   +------+----+
     |                 |
+----+-----------------+-----+
|                            |
|           s1               |
|                            |
+----+------------------+----+
     |                  |
+----+------+    +------+---+
|           |    |          |
|   h1      |    |   h2     |
|   AVP1    |    |   AVP2   |
|           |    |          |
+-----------+    +----------+

"""

TOPOLOGY = """
# Nodes
[type=halon_0 name="OpenSwitch 1" target="true"] ops1
[type=host name="Host 1" image="ubuntuscapy_2.4:latest"] hs1
[type=host name="Host 2" image="ubuntuscapy_2.4:latest"] hs2
[type=host name="Host 3" image="ubuntuscapy_2.4:latest"] hs3
[type=host name="Host 4" image="ubuntuscapy_2.4:latest"] hs4

# Links
ops1:if01 -- hs1:eth1
ops1:if02 -- hs2:eth1
ops1:if03 -- hs3:eth1
ops1:if04 -- hs4:eth1
"""

# Global Variables
AVP_MAC = ""
NVP_MAC = ""
VNI = 1760
UDP_DPORT = 4789
UDP_SPORT = 1234
SRC_IP = ""
DST_IP = ""
OUTER_SRC_MAC = ""
OUTER_DST_MAC = ""
PKT_TYPE = ''

# Global fixed variables
STP_DEST_MAC = "01:80:c2:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MULTICAST_MAC = "01:00:00:00:00:bb"
LLDP_MAC = "01:80:c2:00:00:0e"
AVP1_MAC = "00:00:00:00:00:11"
NVP1_MAC = "00:00:00:00:00:aa"
SW_MAC = ""

# NVP IPs and IPs
# IPs  and MACs only needed for NVPs h3 and h4
HOST3_MAC = ""
HOST4_MAC = ""
H3_IP = '30.0.0.100'
H4_IP = '40.0.0.100'

VTEP_PEER_IP = '20.0.0.2'

# Switch SVI IPs
S1_SVI_IP_1 = '30.0.0.1'
S1_SVI_IP_2 = '40.0.0.1'

# Switch Loopback IP
# Used for VxLAN tunnel Source IP
S1_LO_IP = '1.1.1.1'

MASK = '24'
DEST_MASK = '32'

VLAN1 = '10'
VLAN2 = '30'
VLAN3 = '40'
VNI_HEX = '0x6e0'
TUN_NUM = '1'

PKT_COUNT = 5
SNIFF_PKT_COUNT = 10

# Number of MACs to send for ECMP Loading
TOTAL_MACS = 50

# This timeout parameter is for sending 5 packets
TIMEOUT = 5

# This timeout parameter is for sending 50 packets
LONG_TIMEOUT = 15

# Global dict to store packet count
# Updated in parse_packet function
RECEIVED_PKT_DICT = {}


@fixture(scope='function')
def config(env_setup_hs_sw_hs_hs_hs, request, testlog):
    '''
    Fixture to get the global fixture for this topology and run the teardown

    :param env_setup_hs_sw_hs: global fixture for the topology
    :param request: request param from pytest fixture
    :param testlog: testlog fixture
    '''
    yield env_setup_hs_sw_hs_hs_hs

    testlog.log_step("Teardown")
    env_setup_hs_sw_hs_hs_hs.teardown()


@fixture(scope='function')
def get_switch_mac(topology):
    '''
    Helper function to get mac address from the switch
    '''
    global SW_MAC
    s = topology.get('ops1')
    result = s.libs.vtysh.show_system()
    SW_MAC = result['base_mac']
    yield


@fixture(scope='function')
def get_host_macs(topology):
    '''
    Helper function to get mac addresses for NVP hosts h3 and h4
    '''
    global HOST3_MAC, HOST4_MAC

    h3 = topology.get('hs3')
    h4 = topology.get('hs4')

    h3_port = h3.ports['eth1']
    h4_port = h4.ports['eth1']

    ifconfig = h3.libs.ip.get_ifconfig(h3_port)
    HOST3_MAC = ifconfig[h3_port]['hwaddr']

    ifconfig = h4.libs.ip.get_ifconfig(h4_port)
    HOST4_MAC = ifconfig[h4_port]['hwaddr']
    yield


@fixture(scope='function',
         ids=['l2_basic', 'stp', 'broadcast', 'multicast', 'lldp'],
         params=[TrafficType.l2_basic, TrafficType.stp,
                 TrafficType.broadcast, TrafficType.multicast,
                 TrafficType.lldp])
def traffic_permutation(request):
    """
    Set the global variables for traffic
    """
    global AVP_MAC, NVP_MAC, UDP_SPORT, SRC_IP, DST_IP, OUTER_SRC_MAC,\
        OUTER_DST_MAC, PKT_TYPE

    # Values common to all packet types
    SRC_IP = VTEP_PEER_IP
    DST_IP = S1_LO_IP
    OUTER_SRC_MAC = HOST3_MAC
    OUTER_DST_MAC = SW_MAC
    AVP_MAC = AVP1_MAC

    # NVP_MAC updated based on pkt_type
    NVP_MAC_dict = {TrafficType.l2_basic: NVP1_MAC,
                    TrafficType.stp: STP_DEST_MAC,
                    TrafficType.broadcast: BROADCAST_MAC,
                    TrafficType.multicast: MULTICAST_MAC,
                    TrafficType.lldp: LLDP_MAC}

    PKT_TYPE_dict = {TrafficType.l2_basic: 'l2_basic',
                     TrafficType.stp: 'stp',
                     TrafficType.broadcast: 'broadcast',
                     TrafficType.multicast: 'multicast',
                     TrafficType.lldp: 'lldp'}

    NVP_MAC = NVP_MAC_dict[request.param]
    PKT_TYPE = PKT_TYPE_dict[request.param]

    yield request.param


def generate_params(sw):
    """
    Return arguments required for every single permutation

    :param sw: Topology switch object
    :param permutation: Main pytest fixture for this test
    """

    # List of vlan ids to use for this permutation
    vlan_ids = []
    # Physical ports  required for this permutation per L3 interface
    phy_ports = []
    # L3 interfaces to be created
    l3_interfaces = 0
    # List of ip address for every host
    ip_address_hs = []
    # VxLAN interfaces to be created
    vxlan_ids = []
    # VNIs to be created
    vnis = {}
    # VTEP Peers to be created
    vtep_peers = []

    vlan_ids = [VLAN1, VLAN2, VLAN3]
    vxlan_ids = [TUN_NUM]
    vnis = {VNI: {'vlan': [VLAN1], 'vtep_peer': [VTEP_PEER_IP]}}
    l3_interfaces = 1
    phy_ports = [sw.vtysh_ports['if01'], sw.vtysh_ports['if02'],
                 sw.vtysh_ports['if03'], sw.vtysh_ports['if04']]
    ip_address_hs = [H3_IP, H4_IP]
    vtep_peers = [H3_IP, H4_IP]

    return {'vlan_ids': vlan_ids,
            'vxlan_ids': vxlan_ids,
            'vnis': vnis,
            'vtep_peers': vtep_peers,
            'l3_interfaces': l3_interfaces,
            'phy_ports': phy_ports,
            'ip_address_hs': ip_address_hs}


def configure_host_ips(h3, h4, ip_address_hs):
    """
    Configure host IPs for the NVPs (h3 and h4)
    AVPs do not need IPs assigned for test

    :param h3: A Topology host object
    :param h4: A Topology host object
    :param ip_address_hs: A list of ip addresses to configure h3 and h4
    """

    h3.libs.ip.flush_ip('eth1')
    h3.libs.ip.interface('eth1', up=False)

    h4.libs.ip.flush_ip('eth1')
    h4.libs.ip.interface('eth1', up=False)

    h3.libs.ip.interface(portlbl='eth1', addr="{}/{}".format(
        ip_address_hs[0], MASK), up=True)
    h4.libs.ip.interface(portlbl='eth1', addr="{}/{}".format(
        ip_address_hs[1], MASK), up=True)


def start_stop_scapy_on_hosts(hs, action='start'):
    """
    Function to start and stop scapy daemon on hosts

    :param hs: A Topology host object
    :param action: By default, the value is 'start'
            If set to any other value, scapy will exit
    """
    if action == 'start':
        hs.libs.scapy.start_scapy()
    else:
        hs.libs.scapy.exit_scapy()


def scapy_configuration_avp(hs, pkt_type=None, macsrc=None, macdst=None):
    """
    Function to configure scapy for packet in AVP->All direction

    :param hs: A Topology host object
    :param pkt_type: l2_basic, stp, broadcast, multicast, or lldp
    :param macsrc: Source MAC address
    :param macdst: Destination MAC address
    """
    # L2 header
    eth_header = hs.libs.scapy.ether()

    eth_header['src'] = '{}'.format(macsrc)
    eth_header['dst'] = '{}'.format(macdst)

    if isinstance(macsrc, list):
        eth_header['src'] = macsrc
    packet_list = []
    packet_struct = ""

    # If pkt_type is stp, need additional STP and LLC headers
    if pkt_type == 'stp':
        # Raw data
        stp_header = hs.libs.scapy.stp()
        llc_header = hs.libs.scapy.llc()
        packet_list = [eth_header, llc_header, stp_header]
        packet_struct = "Eth/LLC()/STP()"

    # For all other packet types, packet structure is same
    else:
        # Update raw_data with pkt_type
        raw_data = {'data': "{} packet from AVP end".format(pkt_type)}
        packet_list = [eth_header, raw_data]
        packet_struct = "Eth/data"

    packet = [packet_struct, packet_list]

    return packet


def scapy_configuration_nvp(hs, pkt_type=None,
                            inner_macsrc=None, inner_macdst=None, vni=None,
                            src_port=None, dst_port=None, src_IP=None,
                            dst_IP=None, outer_macsrc=None, outer_macdst=None):
    """
    Function to configure scapy for packet in NVP->All direction

    :param hs: A Topology host object
    :param pkt_type: l2_basic, stp, broadcast, multicast, or lldp
    :param inner_macsrc: Encapsulated packet source MAC address
    :param inner_macdst: Encapsulated packet destination MAC address
    :param vni: VNI value for VxLAN header
    :param src_port: UDP source port
    :param dst_port: UDP destination port
    :param src_IP: Source VTEP's IP
    :param dst_IP: Destination VTEP's IP
    :param inner_macsrc: Source VTEP's MAC address
    :param inner_macdst: Next hop MAC address
    """
    # Inner L2 header
    inner_eth_header = hs.libs.scapy.ether()
    inner_eth_header['prot'] = 'ENCAP_ETH'
    inner_eth_header['src'] = '{}'.format(inner_macsrc)
    inner_eth_header['dst'] = '{}'.format(inner_macdst)

    # VxLAN header
    vxlan_header = hs.libs.scapy.vxlan()
    vxlan_header['vni'] = vni
    vxlan_header['flags'] = 'Instance'
    # UDP header
    udp_header = hs.libs.scapy.udp()
    udp_header['sport'] = src_port
    udp_header['dport'] = dst_port
    # IP header
    ip_header = hs.libs.scapy.ip()
    ip_header['src'] = '{}'.format(src_IP)
    ip_header['dst'] = '{}'.format(dst_IP)
    # Outer L2 header
    outer_eth_header = hs.libs.scapy.ether()
    outer_eth_header['src'] = '{}'.format(outer_macsrc)
    outer_eth_header['dst'] = '{}'.format(outer_macdst)
    outer_eth_header['type'] = 0x0800
    # Inner L2 header
    inner_eth_header['src'] = '{}'.format(inner_macsrc)
    inner_eth_header['dst'] = '{}'.format(inner_macdst)

    # If pkt_type is stp, need additional STP and LLC headers
    if pkt_type == 'stp':
        stp_header = hs.libs.scapy.stp()
        llc_header = hs.libs.scapy.llc()
        packet_list = [outer_eth_header, ip_header, udp_header,
                       vxlan_header, inner_eth_header, llc_header, stp_header]
        packet_struct = "Eth/IP/UDP/VXLAN/ENCAP_ETH/LLC()/STP()"

    # For all other packet types, packet structure is same
    else:
        # Update raw_data with pkt_type
        raw_data = {'data': "{} packet from NVP end".format(pkt_type)}
        packet_list = [outer_eth_header, ip_header, udp_header,
                       vxlan_header, inner_eth_header, raw_data]
        packet_struct = "Eth/IP/UDP/VXLAN/ENCAP_ETH/data"

    packet = [packet_struct, packet_list]
    return packet


def start_traffic(hs, packet, count):
    """
    Start Traffic
    :param hs: Host hs.
    :param packet: Custom header to send.
    :param count: Number of packets to send
    """

    # Waiting 2 sec to give some time to sniffer to be ready
    sleep(2)
    iface = hs.ports['eth1']
    # Start Traffic
    hs.libs.scapy.sendp(packet[0], packet[1],
                        "iface='{}', count = {}, inter=0.2".format(iface, count))


def check_packet(packet, recipient_type, pkt_type, exp_src, exp_dst):
    """
    Helper function to determine how many packets are correctly received.
    Return packet_count

    :param packet: Dictionary of sniffed packets.
    :param recipient_type: String describing if recipient host is an AVP or NVP
    :param pkt_type: l2_basic, stp, broadcast, multicast, or lldp
    :param exp_src: String representing expected source MAC of packet
    :param exp_dst: String representing expected destination MAC of packet
    """
    packet_count = 0

    # If recipient is AVP, check for simple packet
    if ("AVP" in recipient_type):
        for pkt in packet.values():
            # Boolean to store if packet is correct. Set to False initially
            correctly_received = False

            # Check 1: Check src and dst MACs match expected
            if ((pkt['Ethernet']['src'] in exp_src) and
                    (pkt['Ethernet']['dst'] == exp_dst)):

                # Check 2: If packet type is LLDP, check raw string for "lldp"
                if (pkt_type == "lldp"):
                    # If "lldp" is present, set correctly_received to True
                    if ("lldp" in pkt['Ethernet']['Raw']['load']):
                        correctly_received = True

                # Packet type is not LLDP, so only Check 1 is required
                # Set correctly_received to True
                else:
                    correctly_received = True

            # Update total packet count with value of correctly_received
            packet_count += correctly_received

    # If recipient is NVP, then check for VXLAN encapsulated packet
    elif ("NVP" in recipient_type):
        for pkt in packet.values():
            # Boolean to store if packet is correct. Set to False initially
            correctly_received = False

            # Check 1: Check if VxLAN fields are correct
            if ((pkt['Ethernet']['IP']['src'] == S1_LO_IP) and
                (pkt['Ethernet']['IP']['dst'] == VTEP_PEER_IP) and
                (pkt['Ethernet']['IP']['UDP']['dport'] == str(UDP_DPORT)) and
                (pkt['Ethernet']['IP']['UDP']['VXLAN']['vni'] == VNI_HEX) and
                (pkt['Ethernet']['IP']['UDP']['VXLAN']['Ethernet']['src'] in exp_src) and
                    (pkt['Ethernet']['IP']['UDP']['VXLAN']['Ethernet']['dst'] == exp_dst)):

                # Check 2: If packet type is LLDP, check raw string for "lldp"
                if (pkt_type == "lldp"):
                    # If "lldp" is present, set correctly_received to True
                    if ("lldp" in pkt['Ethernet']['IP']['UDP']['VXLAN']['Ethernet']['Raw']['load']):
                        correctly_received = True
                # Packet type is not LLDP, so only Check 1 is required
                # Set correctly_received to True
                else:
                    correctly_received = True

            # Update total packet count with value of correctly_received
            packet_count += correctly_received

    return packet_count


def parse_packet(packet, recipient_type, pkt_type, exp_src, exp_dst, step):
    """
    Function to parse received packets and check if the packet values
    match expected values

    :param packet: Dictionary of sniffed packets.
    :param recipient_type: String describing if host is an AVP or NVP
    :param pkt_type: l2_basic, stp, broadcast, multicast, or lldp
    :param expected_pkts: Boolean stating if we expect packets
    :param exp_src: Expected source MAC of packet
    :param exp_dst: Expected destination MAC of packet
    :param step: Step fixture
    """

    packet_count = 0
    expected_packet_count = PKT_COUNT

    # Calling check_packet helper function to determine how many packets are
    # correctly received. Function returns packet_count
    packet_count = check_packet(
        packet, recipient_type, pkt_type, exp_src, exp_dst)

    # Print packet count at each host
    print("Packet count at {} was {}".format(recipient_type, packet_count))

    # Store packet_counts in global dict RECEIVED_PKT_DICT
    # Dict needed for ECMP check
    RECEIVED_PKT_DICT[recipient_type] = packet_count


def sniff_traffic(hs, count, timeout, recipient_type, pkt_type,
                  exp_src, exp_dst, testlog):
    """
    Sniff traffic on given interface
    :param hs: Host hs.
    :param count: Count of packets to be sniffed
    :param timeout: timeout value
    :param recipient_type: AVP or NVP
    :param pkt_type: l2_basic, stp, broadcast, multicast, or lldp
    :param step: Step fixture
    """
    iface = hs.ports['eth1']

    # If host is NVP, sniff using a filter that checks for UDP packets
    if ("NVP" in recipient_type):
        packet = hs.libs.scapy.sniff2("iface='{}', count={}, timeout={}, "
                                      " filter='port 4789 and (!icmp or !ip6)', "
                                      " prn=lambda x:x.show()".format(
                                          iface, count, timeout), True)
        parse_packet(packet, recipient_type, pkt_type,
                     exp_src, exp_dst, testlog)
    # If host is AVP, sniff using a filter that checks for Ethernet packets
    elif ("AVP" in recipient_type):
        packet = hs.libs.scapy.sniff2("iface='{}', count={}, "
                                      " timeout={}, filter='!icmp or !ip6', "
                                      " prn=lambda x:x.show()".format(
                                          iface, count, timeout), True)
        parse_packet(packet, recipient_type, pkt_type,
                     exp_src, exp_dst, testlog)


def print_transmission_results(pkts_expected_dict,
                               expected_pkt_count, testlog):
    """
    Helper function to display results of packet transmission

    :param pkts_expected_dict: Dictionary of Booleans representing if packets
          are expected at each host (Keys: Host Names, Values: True/False)
    :param expected_pkt_count: Number of packets expected
    :param testlog: Testlog fixture
    """

    # Global Dictionary representing packet count received at each host
    # (Keys: Host Names, Values: Packet Count)
    global RECEIVED_PKT_DICT

    testlog.log_subheader("Results:")

    # If packets are expected at ECMP group
    if (pkts_expected_dict["ECMP group"]):
        # Ensure that one NVP received traffic but not both (XOR)
        assert ((RECEIVED_PKT_DICT["NVP1 (h3)"] == expected_pkt_count) ^
                (RECEIVED_PKT_DICT["NVP2 (h4)"] == expected_pkt_count)), \
            "Packets expected at ECMP group, but incorrectly received. " + \
            "Check packet count at the NVPs"
        testlog.log_info("Packets correctly received at the ECMP group. " +
                         "Only one NVP received traffic")
    # Packets were not expected at the ECMP group
    else:
        testlog.log_info("Packets were not expected at the ECMP group")

    # If packets are expected at AVP1 and packets were received
    if (pkts_expected_dict["AVP1"]) and ("AVP1 (h1)" in RECEIVED_PKT_DICT.keys()):
        # Check received packet count matches expected packet count
        assert ((RECEIVED_PKT_DICT["AVP1 (h1)"] == expected_pkt_count)),\
            "Packets expected at AVP1, but incorrectly received. " + \
            "Check packet count at the AVP1"
        testlog.log_info("Packets correctly received at AVP1")
    # Packets were not expected at AVP1
    else:
        testlog.log_info("Packets were not expected at AVP1")

    # If packets are expected at AVP2 and packets were received
    if (pkts_expected_dict["AVP2"]) and ("AVP2 (h2)" in RECEIVED_PKT_DICT.keys()):
        # Check received packet count matches expected packet count
        assert ((RECEIVED_PKT_DICT["AVP2 (h2)"] == expected_pkt_count)),\
            "Packets expected at AVP2, but incorrectly received. " + \
            "Check packet count at the AVP2"
        testlog.log_info("Packets correctly received at AVP2")
    # Packets were not expected at AVP2
    else:
        testlog.log_info("Packets were not expected at AVP2")


def check_load_balancing(testlog):
    """
    Helper function to parse RECEIVED_PKT_DICT and report on
    if NVP1 or NVP2 is chosen

    :param testlog: testlog fixture
    """

    # Global Dictionary representing packet count received at each host
    # (Keys: Host Names, Values: Packet Count)
    global RECEIVED_PKT_DICT

    testlog.log_step("Final ECMP Load Balancing Results")
    NVP1_count = RECEIVED_PKT_DICT["NVP1 (h3)"]
    NVP2_count = RECEIVED_PKT_DICT["NVP2 (h4)"]
    NVP1_percent = (NVP1_count/TOTAL_MACS)*100
    NVP2_percent = (NVP2_count/TOTAL_MACS)*100

    print("NVP1 was chosen {} out of {} times, which is {:.2f}% of the time\n".format(
        NVP1_count, TOTAL_MACS, NVP1_percent))
    print("NVP2 was chosen {} out of {} times, which is {:.2f}% of the time\n".format(
        NVP2_count, TOTAL_MACS, NVP2_percent))

    # Check ECMP Load Balancing if expected
    if (PKT_TYPE == "l2_basic"):
        # Check if at least 40% of total packets were received at one host
        # Check that total NVP1_count and NVP2_count equals the number of packets
        assert((NVP1_percent >= 0.4) or (NVP2_percent >= 0.4) and
               ((NVP1_count + NVP2_count) == TOTAL_MACS)),\
            "ECMP Load Balancing Failed for Known Unicast Traffic"

        step_desc = "ECMP Load Balancing check passed for Known Unicast traffic"
        testlog.log_info(step_desc)
    else:
        # Check that all of the packets are only received at one NVP and
        # zero packets are received at the other NVP
        assert(((NVP1_count == 0) and (NVP2_count == TOTAL_MACS)) or
               (NVP2_count == 0) and (NVP1_count == TOTAL_MACS)), \
            "Load Balancing was not expected, but packets were not" +\
            " received correctly for {} traffic".format(PKT_TYPE)

        step_desc = "Load Balancing is not expected for {} traffic. ".format(PKT_TYPE) + \
                    "All traffic was directed to the BUM Next Hop"
        testlog.log_info(step_desc)


@mark.timeout(1000)
def test_ft_VxLAN_TrafficMultiAVPNVP(topology,
                                     testlog,
                                     config,
                                     get_switch_mac,
                                     get_host_macs,
                                     traffic_permutation,
                                     l2_basic_phy,
                                     l3_basic_phy):
    """
    Test sends different types of traffic between 4 hosts connected
    through VxLAN tunnel.

    Build a topology of one switch and four hosts and connect
    the hosts to the switches.
    Setup a VxLAN between switches and VLANs between ports
    and switches.
    """

    """
    Step: Create the topology as shown
    Result: Topology created successfully
    """
    testlog.log_step("Set up the switch and hosts")
    s1 = topology.get('ops1')
    h1 = topology.get('hs1')
    h2 = topology.get('hs2')
    h3 = topology.get('hs3')
    h4 = topology.get('hs4')

    argv = generate_params(s1)

    """
    Step: Configure the topology as shown
    Result: Topology has been configured successfully
    """
    # Configuring VLAN and four interfaces on switch 1
    testlog.log_subheader("Creating L2 Interfaces")
    config.create_l2_interface_type(s1,
                                    l2_basic_phy['l2_iface'],
                                    False, False,
                                    [argv['phy_ports'][0]],
                                    argv['vlan_ids'][0],
                                    None, testlog)

    config.create_l2_interface_type(s1,
                                    l2_basic_phy['l2_iface'],
                                    False, False,
                                    [argv['phy_ports'][1]],
                                    argv['vlan_ids'][0],
                                    None, testlog)

    testlog.log_subheader("Creating SVIs")
    # Creating SVI interfaces of if03 and if04
    config.create_l2_interface_type(s1,
                                    l2_basic_phy['l2_iface'],
                                    False, False,
                                    [argv['phy_ports'][2]],
                                    argv['vlan_ids'][1],
                                    None, testlog)

    config.create_l2_interface_type(s1,
                                    l2_basic_phy['l2_iface'],
                                    False, False,
                                    [argv['phy_ports'][3]],
                                    argv['vlan_ids'][2],
                                    None, testlog)

    configure_switch_vlan(s1,
                          argv['vlan_ids'][1],
                          S1_SVI_IP_1 + '/' + MASK,
                          [argv['phy_ports'][2]])

    configure_switch_vlan(s1,
                          argv['vlan_ids'][2],
                          S1_SVI_IP_2 + '/' + MASK,
                          [argv['phy_ports'][3]])

    testlog.log_subheader("Creating Switch Loopback Interface")
    # Creating a loopback interface on s1
    config.create_l3_loopback(s1,
                              '0',
                              S1_LO_IP + '/' + MASK)

    testlog.log_subheader("Configure Host IPs")
    configure_host_ips(h3, h4, argv['ip_address_hs'])

    testlog.log_subheader("Configuring IP Routes from NVPs to 20.0.0.2")
    config.switch_add_route(s1, VTEP_PEER_IP, DEST_MASK, H3_IP)
    config.switch_add_route(s1, VTEP_PEER_IP, DEST_MASK, H4_IP)

    """
    Step: Configure VxLAN interface on switch 1
    Result: VxLAN interface has been configured successfully
    """
    testlog.log_step("Configure VXLAN")
    config.configure_vxlan(s1,
                           TUN_NUM,
                           S1_LO_IP,
                           argv['vnis'])
    testlog.log_subheader("Current Running Configuration")
    s1.libs.vtysh.show_running_config()

    """
    Step:   Generate traffic type using Scapy on all hosts
    Result: Traffic successfully created
    """
    testlog.log_step("Start Scapy on hosts")
    # Starting scapy
    start_stop_scapy_on_hosts(h1)
    start_stop_scapy_on_hosts(h2)
    start_stop_scapy_on_hosts(h3)
    start_stop_scapy_on_hosts(h4)

    """
    Step:   Use scapy to configure the traffic from AVP to all hosts
    Result: Packet created
    """
    # Configure Scapy on hs1 for AVP-->All traffic
    step_desc = "Configure traffic from AVP1"
    testlog.log_step(step_desc)

    cur_src_MAC = AVP_MAC
    cur_dst_MAC = NVP_MAC
    packet_avp = scapy_configuration_avp(h1, pkt_type=PKT_TYPE,
                                         macsrc=cur_src_MAC, macdst=cur_dst_MAC)

    """
    Step:   Transmit the traffic from AVP to all hosts and
            parse the captured packet to check
            if the packet is received as expected
    Result: Traffic transmitted successfully and
            Correct values received
    """

    # Updating step_desc based on traffic type
    if (PKT_TYPE == "l2_basic"):
        step_desc = "Transmit from AVP1 (Packet Type: Unknown Unicast)\n" + \
                    "\t     Intended Receivers: AVP2, NVP1/NVP2"
    else:
        step_desc = "Transmit from AVP1 (Packet Type: {})\n".format(PKT_TYPE) + \
                    "\t     Intended Receivers: AVP2, NVP1/NVP2"

    testlog.log_step(step_desc)

    # Dictionary of Booleans for each host
    # True means Packet expected at host and False: Packets not expected at host
    pkts_expected_dict = {"AVP1": False, "AVP2": True, "ECMP group": True}
    # Sending traffic from AVP h1 to all other hosts
    with ThreadGroup() as ctx:
        # Sniffing on hs2 (AVP)
        ctx.run(sniff_traffic, hs=h2, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="AVP2 (h2)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on hs3 (NVP)
        ctx.run(sniff_traffic, hs=h3, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="NVP1 (h3)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on hs4 (NVP)
        ctx.run(sniff_traffic, hs=h4, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="NVP2 (h4)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        ctx.run(start_traffic, hs=h1, packet=packet_avp, count=PKT_COUNT)

    # Checking Transmission Results
    print_transmission_results(pkts_expected_dict, PKT_COUNT, testlog)

    print(RECEIVED_PKT_DICT)
    RECEIVED_PKT_DICT.clear()

    """
    Step:   Check if MAC is learnt as expected
    Result: Source MAC is present in switch MAC table
    """
    testlog.log_step("Check MAC Learning")
    # Verifying if MAC A was learned on if01
    verify_mac = retry(
        stop_max_attempt_number=3,
        wait_fixed=1000)(verify_mac_table)
    verify_mac(sw1=s1, mac=cur_src_MAC, exp_port=argv['phy_ports'][0],
               exp_vlan=VLAN1, vtep_peer=None)

    # Update src MAC and dst MAC based on packet type
    dst_MAC_dict = {"l2_basic": AVP1_MAC, "stp": STP_DEST_MAC,
                    "broadcast": BROADCAST_MAC, "multicast": MULTICAST_MAC,
                    "lldp": LLDP_MAC}

    cur_src_MAC = NVP1_MAC
    cur_dst_MAC = dst_MAC_dict[PKT_TYPE]

    """
    Step:   Use scapy to configure the traffic for NVP to all hosts
    Result: Packet created
    """
    step_desc = "Configure traffic from NVP1"
    testlog.log_step(step_desc)

    # Configure Scapy on hs1 for NVP-->All traffic
    packet_nvp = scapy_configuration_nvp(h3, pkt_type=PKT_TYPE,
                                         inner_macsrc=cur_src_MAC,
                                         inner_macdst=cur_dst_MAC, vni=VNI,
                                         src_port=UDP_SPORT, dst_port=UDP_DPORT,
                                         src_IP=SRC_IP, dst_IP=DST_IP,
                                         outer_macsrc=OUTER_SRC_MAC,
                                         outer_macdst=OUTER_DST_MAC)

    """
    Step:   Transmit the traffic from NVP to all hosts and
            parse the captured packet to check
            if the packet is received as expected
    Result: Traffic transmitted successfully and
            Correct values received
    """
    # Updating step_desc based on traffic type
    if (PKT_TYPE == "l2_basic"):
        step_desc = "Transmit from NVP1 (Packet Type: Known Unicast)\n" + \
                    "\t     Intended Receivers: AVP1"
    else:
        step_desc = "Transmit from NVP1 (Packet Type: {})\n".format(PKT_TYPE) + \
                    "\t     Intended Receivers: AVP1, AVP2"
    testlog.log_step(step_desc)

    # If broadcast, multicast or BPDU, packet is flooded to both AVPs
    pkts_expected_dict = {"AVP1": True, "AVP2": True, "ECMP group": False}

    # If l2 basic, packet is known unicast packet and only received at AVP1
    if (PKT_TYPE == "l2_basic"):
        pkts_expected_dict = {"AVP1": True, "AVP2": False, "ECMP group": False}

    # Sending traffic from NVP1 h3 to all other hosts
    with ThreadGroup() as ctx:
        # Sniffing on h1 (AVP1)
        ctx.run(sniff_traffic, hs=h1, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="AVP1 (h1)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on h2 (AVP2)
        ctx.run(sniff_traffic, hs=h2, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="AVP2 (h2)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on h4 (NVP2)
        ctx.run(sniff_traffic, hs=h4, count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                recipient_type="NVP2 (h4)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        ctx.run(start_traffic, hs=h3, packet=packet_nvp, count=PKT_COUNT)

    # Checking Transmission Results
    print_transmission_results(pkts_expected_dict, PKT_COUNT, testlog)
    print(RECEIVED_PKT_DICT)
    RECEIVED_PKT_DICT.clear()

    """
    Step:   Check if MAC is learnt as expected
    Result: Source MAC is present in switch MAC table
    """

    testlog.log_step("Check MAC Learning")
    # Verifying if NVP1_MAC was learned on interface vxlan 1
    verify_mac(sw1=s1, mac=cur_src_MAC, exp_port="vxlan1",
               exp_vlan=VLAN1, vtep_peer=VTEP_PEER_IP)

    """
    Step:   Transmit the traffic from NVP to all hosts and
            parse the captured packet to check
            if the packet is received as expected
    Result: Traffic transmitted successfully and
            Correct values received
    """
    # Updating step_desc based on traffic type
    step_desc = "Transmit from AVP1. Permuting Source MAC to Test ECMP Load Balancing"
    testlog.log_step(step_desc)

    # If broadcast, multicast or BPDU, packet is sent to AVP2 and ECMP group
    pkts_expected_dict = {"AVP1": False, "AVP2": True, "ECMP group": True}

    # If l2 basic, packet is known unicast packet and only received at ECMP group
    if (PKT_TYPE == "l2_basic"):
        pkts_expected_dict = {"AVP1": True, "AVP2": False, "ECMP group": True}

    # Creating a list of potential source MACs
    lst_source_macs = ['00:00:00:00:00:{}'.format(
        i) for i in range(21, 21+TOTAL_MACS)]
    cur_src_MAC = lst_source_macs
    cur_dst_MAC = NVP_MAC

    packet_avp_lst = scapy_configuration_avp(h1, pkt_type=PKT_TYPE,
                                             macsrc=cur_src_MAC, macdst=cur_dst_MAC)

    with ThreadGroup() as ctx:
        # Sniffing on hs2 (AVP)
        ctx.run(sniff_traffic, hs=h2, count=TOTAL_MACS+10, timeout=LONG_TIMEOUT,
                recipient_type="AVP2 (h2)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on hs3 (NVP)
        ctx.run(sniff_traffic, hs=h3, count=TOTAL_MACS+10, timeout=LONG_TIMEOUT,
                recipient_type="NVP1 (h3)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        # Sniffing on hs4 (NVP)
        ctx.run(sniff_traffic, hs=h4, count=TOTAL_MACS+10, timeout=LONG_TIMEOUT,
                recipient_type="NVP2 (h4)", pkt_type=PKT_TYPE,
                exp_src=cur_src_MAC, exp_dst=cur_dst_MAC, testlog=testlog)
        ctx.run(start_traffic, hs=h1, packet=packet_avp_lst, count=1)

    print(RECEIVED_PKT_DICT)

    # Call check_load_balancing helper function to
    check_load_balancing(testlog)

    RECEIVED_PKT_DICT.clear()
    testlog.log_step("Stop Scapy on hosts")
    # Stopping scapy
    start_stop_scapy_on_hosts(h1, action='stop')
    start_stop_scapy_on_hosts(h2, action='stop')
    start_stop_scapy_on_hosts(h3, action='stop')
    start_stop_scapy_on_hosts(h4, action='stop')
