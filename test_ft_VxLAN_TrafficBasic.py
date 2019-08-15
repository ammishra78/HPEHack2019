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
    PortType,
    TrafficType,
    verify_mac_table
)
from topology_common.ops.l3_common.ft_l3_lib import (
    AddressType
)
from topology_common.ops.vlans.vlan import configure_switch_vlan

from fixtures import (
    env_setup_hs_sw_hs,
    l2_basic_phy,
    l3_basic_phy)

__doc__ = """
Test Case Header:
=================
:Author: Surbhit Sinha - surbhit.sinha@hpe.com
:TestId: 00000
:Release: 10_04
:TestName: test_ft_VxLAN_TrafficBasic
:Objective: Verify VXLAN encapsulation and decapsulation
:Requirements:
    - 1 switch
    - 2 hosts
:TestDescription: This test-case verifies VXLAN encapsulation is working for
    different traffic types on AVP-->NVP direction and decapsulation for
    NVP-->AVP direction

    1.  Setup the topology as shown and enable all interfaces.
    2.  Configure VXLAN on the switch
    3.  Send packet from AVP to NVP and verify encapsulation
    4.  Send encapsulated packet from NVP to AVP direction and verify that
        the packet is correctly decpasulated.
:PlanPriority: 3 - High
:TestPassCriteria: -
    1. Setup of the topology successfully created.
    2. Packet successfully encapsulated at NVP end.
    3. Packet successfully decapsulated at AVP end.
:PlatformIndependent: Y
:SupportedPlatforms: 8325; 8360; 6300; 6400
Topology:
=========
.. ditaa::

+-------+                    +-------+
|       |     +--------+     |       |
|  h1   +-----+   s1   +-----+  h2   |
|       |     +--------+     |       |
+-------+                    +-------+

"""

TOPOLOGY = """
# Nodes
[type=halon_0 name="OpenSwitch 1" target="true"] ops1
[type=host name="Host 1" image="ubuntuscapy_2.4:latest"] hs1
[type=host name="Host 1" image="ubuntuscapy_2.4:latest"] hs2

# Links
hs1:eth1 -- ops1:if01
ops1:if02 -- hs2:eth1
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
PORT_TYPE = ''

# Global fixed variables
HOST1_MAC = ""
HOST2_MAC = ""
SW_MAC = ""
STP_DEST_MAC = "01:80:c2:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MULTICAST_MAC = "01:00:00:00:00:bb"
LLDP_MAC = "01:80:c2:00:00:0e"
MAC_A = "00:00:00:00:00:11"
MAC_B = "00:00:00:00:00:bb"
S1_IP = '12.0.0.1'
H1_IP = '11.0.0.10'
H2_IP = '12.0.0.20'
S1_SVI_IP = '12.0.0.1'
S1_LO_IP = '10.0.0.1'
MASK = '24'
LO_MASK = '32'
VLAN1 = '10'
VLAN2 = '20'
VNI_HEX = '0x6e0'
TUN_NUM = '1'

PKT_COUNT = 5
SNIFF_PKT_COUNT = 10
TIMEOUT = 3


@fixture(scope='function')
def config(env_setup_hs_sw_hs, request, testlog):
    '''
    Fixture to get the global fixture for this topology and run the teardown

    :param env_setup_hs_sw_hs: global fixture for the topology
    :param request: request param from pytest fixture
    '''
    yield env_setup_hs_sw_hs

    testlog.log_step("Teardown")
    env_setup_hs_sw_hs.teardown()


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
    Helper function to get mac addresses from hosts
    '''
    global HOST1_MAC, HOST2_MAC
    h1 = topology.get('hs1')
    h2 = topology.get('hs2')

    h1_port = h1.ports['eth1']
    h2_port = h2.ports['eth1']
    ifconfig = h1.libs.ip.get_ifconfig(h1_port)
    HOST1_MAC = ifconfig[h1_port]['hwaddr']
    ifconfig = h2.libs.ip.get_ifconfig(h2_port)
    HOST2_MAC = ifconfig[h2_port]['hwaddr']
    yield


@fixture(scope='function',
         ids=['rop', 'loopback', 'svi'],
         params=[PortType.rop, PortType.loopback, PortType.svi])
def port_permutation(request):
    """
    Set the global variables for the ports"
    """
    global DST_IP, PORT_TYPE

    # DST_IP updated based on port_type
    DST_IP_dict = {PortType.rop: S1_IP, PortType.loopback: S1_LO_IP,
                   PortType.svi: S1_SVI_IP}
    PORT_TYPE_dict = {PortType.rop: 'rop', PortType.loopback: 'loopback',
                      PortType.svi: 'svi'}

    DST_IP = DST_IP_dict[request.param]
    PORT_TYPE = PORT_TYPE_dict[request.param]
    yield request.param


@fixture(scope='function',
         ids=['l2_basic', 'stp', 'broadcast', 'multicast', 'lldp'],
         params=[TrafficType.l2_basic, TrafficType.stp,
                 TrafficType.broadcast, TrafficType.multicast,
                 TrafficType.lldp])
def traffic_permutation(request):
    """
    Set the global variables for traffic
    """
    global AVP_MAC, NVP_MAC, UDP_SPORT, SRC_IP, OUTER_SRC_MAC,\
        OUTER_DST_MAC, PKT_TYPE

    # Values common to all packet types
    AVP_MAC = MAC_A
    SRC_IP = H2_IP
    OUTER_SRC_MAC = HOST2_MAC
    OUTER_DST_MAC = SW_MAC

    # NVP_MAC updated based on pkt_type
    NVP_MAC_dict = {TrafficType.l2_basic: MAC_B,
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
    # List of ip address required for this permutation
    ip_address_sw = []
    # List of ip address for every host
    ip_address_hs = []
    # VxLAN interfaces to be created
    vxlan_ids = []
    # VNIs to be created
    vnis = {}
    # VTEP Peers to be created
    vtep_peers = []

    vlan_ids = [VLAN1, VLAN2]
    vxlan_ids = [TUN_NUM]
    vnis = {VNI: {'vlan': [VLAN1], 'vtep_peer': [H2_IP]}}
    l3_interfaces = 1
    phy_ports = [sw.vtysh_ports['if01'], sw.vtysh_ports['if02']]
    ip_address_sw = [S1_IP]
    ip_address_hs = [H1_IP, H2_IP]
    vtep_peers = [H2_IP]

    return {'vlan_ids': vlan_ids,
            'vxlan_ids': vxlan_ids,
            'vnis': vnis,
            'vtep_peers': vtep_peers,
            'l3_interfaces': l3_interfaces,
            'phy_ports': phy_ports,
            'ip_address_sw': ip_address_sw,
            'ip_address_hs': ip_address_hs}


def configure_host_ips(h1, h2, ip_address_hs, step):
    """
    Configure host IPs

    :param hs1: A Topology host object
    :param hs2: A Topology host object
    :param ip_address_hs: A list of ip addresses to configure hs1 and hs2
    :param step: Step fixture
    """

    h1.libs.ip.flush_ip('eth1')
    h1.libs.ip.interface('eth1', up=False)

    h2.libs.ip.flush_ip('eth1')
    h2.libs.ip.interface('eth1', up=False)

    step("Configure hosts IPs")
    h1.libs.ip.interface(portlbl='eth1', addr="{}/{}".format(
        ip_address_hs[0], MASK), up=True)
    h2.libs.ip.interface(portlbl='eth1', addr="{}/{}".format(
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
    Function to configure scapy for packet in AVP->NVP direction

    :param hs: A Topology host object
    :param pkt_type: To differentiate between different traffic types
    :param macsrc: Source MAC address
    :param macdst: Destination MAC address
    """
    # L2 header
    eth_header = hs.libs.scapy.ether()
    eth_header['src'] = '{}'.format(macsrc)
    eth_header['dst'] = '{}'.format(macdst)
    packet_list = []
    packet_struct = ""

    # stp packets need stp and llc headers
    if pkt_type == 'stp':
        stp_header = hs.libs.scapy.stp()
        llc_header = hs.libs.scapy.llc()
        packet_list = [eth_header, llc_header, stp_header]
        packet_struct = "Eth/LLC()/STP()"
    # The other packet types have the same structure
    else:
        # Raw data
        raw_data = {'data': "Encapsulated {} packet".format(pkt_type)}
        packet_list = [eth_header, raw_data]
        packet_struct = "Eth/data"

    packet = [packet_struct, packet_list]
    return packet


def scapy_configuration_nvp(hs, pkt_type=None,
                            inner_macsrc=None, inner_macdst=None, vni=None,
                            src_port=None, dst_port=None, src_IP=None, dst_IP=None,
                            outer_macsrc=None, outer_macdst=None):
    """
    Function to configure scapy for packet in NVP->AVP direction

    :param hs: A Topology host object
    :param pkt_type: To differentiate between different traffic types
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

    # stp packets need stp and llc headers
    if pkt_type == 'stp':
        stp_header = hs.libs.scapy.stp()
        llc_header = hs.libs.scapy.llc()
        packet_list = [outer_eth_header, ip_header, udp_header,
                       vxlan_header, inner_eth_header, llc_header, stp_header]
        packet_struct = "Eth/IP/UDP/VXLAN/ENCAP_ETH/LLC()/STP()"
    # The other packet types have the same structure
    else:
        # Raw data
        raw_data = {'data': "Decapsulated {} packet".format(pkt_type)}
        packet_list = [outer_eth_header, ip_header, udp_header,
                       vxlan_header, inner_eth_header, raw_data]
        packet_struct = "Eth/IP/UDP/VXLAN/ENCAP_ETH/data"

    packet = [packet_struct, packet_list]
    return packet


def start_traffic(hs, packet):
    """
    Start Traffic
    :param h1: Host hs.
    :param packet_list: Custom header to send.
    """

    # Waiting 2 sec to give some time to sniffer to be ready
    sleep(2)
    iface = hs.ports['eth1']
    # Start Traffic
    hs.libs.scapy.sendp(packet[0], packet[1],
                        "iface='{}', count = {}, inter = 0.1"
                        .format(iface, PKT_COUNT))


def parse_packet(packet, traffic_type, pkt_type, exp_dst, step):
    """
    Function to parse received packets and check if the packet values
    match expected values
    :param packet: Dictionary of sniffed packets.
    :param traffic_type: Traffic direction (AVP->NVP or NVP->AVP)
    :param pkt_type: Types of traffic that can be sniffed.
    :param exp_dst: Expected destination MAC of packets
    :param step: Step fixture
    """
    packet_count = 0
    if(traffic_type == "encap"):
        if(pkt_type == "stp"):
            for i in packet:
                if ((packet[i]['Ethernet']['IP']['src'] == DST_IP) and
                    (packet[i]['Ethernet']['IP']['dst'] == H2_IP) and
                    (packet[i]['Ethernet']['IP']['UDP']['dport'] ==
                     str(UDP_DPORT)) and
                    (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                     ['vni'] == VNI_HEX) and
                    (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                     ['Ethernet']['src'] == MAC_A) and
                    (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                     ['Ethernet']['dst'] == STP_DEST_MAC) and
                        (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                         ['Ethernet']['type'] == '0x8870')):
                    packet_count += 1
        else:
            for i in packet:
                if ((packet[i]['Ethernet']['IP']['src'] == DST_IP) and
                    (packet[i]['Ethernet']['IP']['dst'] == H2_IP) and
                    (packet[i]['Ethernet']['IP']['UDP']['dport'] ==
                     str(UDP_DPORT)) and
                    (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                     ['vni'] == VNI_HEX) and
                    (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                     ['Ethernet']['src'] == MAC_A) and
                        (packet[i]['Ethernet']['IP']['UDP']['VXLAN']
                         ['Ethernet']['dst'] == exp_dst)):
                    packet_count += 1

        assert (packet_count == PKT_COUNT), 'Incorrect encapsulation'
        print("Correct encapsulation")

    elif(traffic_type == "decap"):
        if(pkt_type == "stp"):
            for i in packet:
                if ((packet[i]['Ethernet']['src'] == MAC_B) and
                    (packet[i]['Ethernet']['dst'] == STP_DEST_MAC) and
                        (packet[i]['Ethernet']['type'] == '0x8870')):
                    packet_count += 1
        else:
            for i in packet:
                if ((packet[i]['Ethernet']['src'] == MAC_B) and
                        (packet[i]['Ethernet']['dst'] == exp_dst)):
                    packet_count += 1

        assert (packet_count == PKT_COUNT), 'Incorrect decapsulation'
        print("Correct decapsulation")


def sniff_traffic(hs, count, timeout, traffic_type, pkt_type, exp_dst, step):
    """
    Sniff traffic on given interface
    :param hs: Host hs.
    :param count: Count of packets to be sniffed
    :param timeout: timeout value
    :param traffic_type: Traffic direction (AVP->NVP or NVP->AVP)
    :param pkt_type: Types of traffic that can be sniffed.
    :param exp_dst: Expected destination MAC of packets
    :param step: Step fixture
    """
    iface = hs.ports['eth1']
    step('Scapy capture started')
    if (traffic_type == "encap"):
        packet = hs.libs.scapy.sniff2("iface='{}', count={}, timeout={}, "
                                      " filter='port 4789 and (!icmp or !ip6)', "
                                      " prn=lambda x:x.show()".format(
                                          iface, count, timeout), True)
        parse_packet(packet, traffic_type, pkt_type, exp_dst, step=step)
    elif (traffic_type == "decap"):
        packet = hs.libs.scapy.sniff2("iface='{}', count={}, "
                                      " timeout={}, filter='!icmp or !ip6', "
                                      " prn=lambda x:x.show()".format(
                                          iface, count, timeout), True)
        parse_packet(packet, traffic_type, pkt_type, exp_dst, step=step)


@mark.timeout(1000)
def test_ft_vxlan_trafficbasic(topology,
                               testlog,
                               config,
                               get_switch_mac,
                               get_host_macs,
                               port_permutation,
                               traffic_permutation,
                               l2_basic_phy,
                               l3_basic_phy):
    """
    Test sends different types of traffic between 2 hosts connected
    through VxLAN tunnel.

    Build a topology of one switch and two hosts and connect
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

    argv = generate_params(s1)

    """
    Step: Configure the topology as shown
    Result: Topology has been configured successfully
    """
    # Configuring VLANs and two interfaces on switch 1

    config.create_l2_interface_type(s1,
                                    l2_basic_phy['l2_iface'],
                                    False, False,
                                    [argv['phy_ports'][0]],
                                    argv['vlan_ids'][0],
                                    None, testlog)

    if PORT_TYPE == 'rop' or PORT_TYPE == 'loopback':
        ip_address = ['{}/{}'.format(argv['ip_address_sw'][0], MASK)]

        config.create_l3_interface_type(s1,
                                        l3_basic_phy['l3_iface'],
                                        'default',
                                        ip_address[0],
                                        AddressType.Primary,
                                        False,
                                        l3_basic_phy['l2_iface'],
                                        [argv['phy_ports'][1]],
                                        None,
                                        None, testlog)

        if PORT_TYPE == 'loopback':
            config.create_l3_loopback(s1,
                                      '0',
                                      S1_LO_IP + '/' + LO_MASK)

    if PORT_TYPE == 'svi':
        config.create_l2_interface_type(s1,
                                        l2_basic_phy['l2_iface'],
                                        False, False,
                                        [argv['phy_ports'][1]],
                                        argv['vlan_ids'][1],
                                        None, testlog)

        configure_switch_vlan(s1,
                              argv['vlan_ids'][1],
                              S1_SVI_IP + '/' + MASK,
                              [argv['phy_ports'][1]])

    """
    Step:   Based on current permutation, configure Host1
            and Host2 IP Addresses
    Result: The hosts were configured correctly
    """
    configure_host_ips(
        h1, h2, argv['ip_address_hs'], testlog)

    """
    Step: Configure VxLAN interface on switch 1
    Result: VxLAN interface has been configured successfully
    """
    testlog.log_step("Configure VxLAN")
    # Configure tunnel interface

    config.configure_vxlan(s1,
                           TUN_NUM,
                           DST_IP,
                           argv['vnis'])

    """
    Step:   Generate traffic type using Scapy on hs1
    Result: Traffic successfully created
    """
    testlog.log_step("Start Scapy on hosts")
    # Starting scapy
    start_stop_scapy_on_hosts(h1)
    start_stop_scapy_on_hosts(h2)

    # Configure Scapy on hs1 for AVP-->NVP traffic
    testlog.log_step("Configure traffic for AVP-->NVP direction")
    packet_avp = scapy_configuration_avp(h1, pkt_type=PKT_TYPE,
                                         macsrc=AVP_MAC, macdst=NVP_MAC)

    """
    Step:   Transmit the traffic from AVP to NVP and
            Parse the captured packet on NVP to check
            if the packet is correctly encapsulated
    Result: Traffic transmitted successfully and
            Correct values received
    """
    testlog.log_step("Transmit and sniff traffic in AVP-->NVP direction")
    with ThreadGroup() as ctx:
        ctx.run(sniff_traffic, hs=h2,
                count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                traffic_type="encap", pkt_type=PKT_TYPE,
                exp_dst=NVP_MAC, step=testlog)
        ctx.run(start_traffic, hs=h1, packet=packet_avp)

    """
    Step:   Check if MAC is learnt as expected
    Result: Source MAC is present in switch MAC table
    """
    testlog.log_step("Checking MAC Learning")
    # Verifying if MAC A was learned on if01
    verify_mac = retry(
        stop_max_attempt_number=5,
        wait_fixed=1000)(verify_mac_table)
    verify_mac(sw1=s1, mac=MAC_A, exp_port=argv['phy_ports'][0],
               exp_vlan=VLAN1, vtep_peer=None)

    """
    Step:   Generate traffic type using Scapy on hs2
    Result: Traffic successfully created
    """
    testlog.log_step("Configure traffic for NVP-->AVP direction")
    # Configure Scapy on hs1 for NVP-->AVP traffic
    macdst_dict = {"l2_basic": MAC_A, "stp": STP_DEST_MAC,
                   "broadcast": BROADCAST_MAC, "multicast": MULTICAST_MAC,
                   "lldp": LLDP_MAC}
    cur_macsrc = MAC_B
    cur_macdst = macdst_dict[PKT_TYPE]

    packet_nvp = scapy_configuration_nvp(h2, pkt_type=PKT_TYPE,
                                         inner_macsrc=cur_macsrc,
                                         inner_macdst=cur_macdst, vni=VNI,
                                         src_port=UDP_SPORT, dst_port=UDP_DPORT,
                                         src_IP=SRC_IP, dst_IP=DST_IP,
                                         outer_macsrc=OUTER_SRC_MAC,
                                         outer_macdst=OUTER_DST_MAC)
    """
    Step:   Transmit the traffic from NVP to AVP and
            Parse the captured packet on AVP to check
            if the the packet is as expected
    Result: Traffic transmitted successfully and
            Correct values received
    """
    testlog.log_step("Transmit and sniff traffic in NVP-->AVP direction")
    with ThreadGroup() as ctx:
        ctx.run(sniff_traffic, hs=h1,
                count=SNIFF_PKT_COUNT, timeout=TIMEOUT,
                traffic_type="decap", pkt_type=PKT_TYPE,
                exp_dst=cur_macdst, step=testlog)
        ctx.run(start_traffic, hs=h2, packet=packet_nvp)

    """
    Step:   Check if MAC is learnt as expected
    Result: Source MAC is present in switch MAC table
    """
    testlog.log_step("Checking MAC Learning")
    # Verifying if MAC B was learned on interface vxlan 1
    verify_mac(sw1=s1, mac=MAC_B, exp_port="vxlan1",
               exp_vlan=VLAN1, vtep_peer=H2_IP)

    testlog.log_step("Stop Scapy on hosts")
    # Stopping scapy
    start_stop_scapy_on_hosts(h1, action='stop')
    start_stop_scapy_on_hosts(h2, action='stop')
