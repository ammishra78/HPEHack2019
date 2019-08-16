# -*- coding: utf-8 -*-
#
# (c) Copyright 2016,2018-2019 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

#

from pytest import mark
from vxlan_utils import (switch_ping,
                         host_negative_ping,
                         host_ping)

__doc__ = """
Test Case Header:
=========================================================================
:Author: Madhulika Madishetty - madhulika.madishetty@hpe.com
:TestId: 89717
:Release: 10_02
:TestName: ft_Vxlan_TunnelBasic.py
:Objective: This test-case checks for the basic VxLAN functionality
:Requirements:
    - 2 VxLAN cabable switches
    - 2 hosts
:TestDescription: Create, modify, and delete a VxLAN tunnel and try
    to ping.
:PlanPriority: 3 - High
:TestPassCriteria:
    1. Setup of the topology successfully created.
    2. Creationg of VxLAN interface was successful
    3. Ping through VxLAN interface was successful
    4. Modify source ip was successful
    5. Ping after modifying source ip was successful
    6. Deletion of the VxLAN interface from the switches was successful
    7. Ping fails without the VxLAN interface
:PlatformIndependent: N
:SupportedPlatforms: 8325W; 8325; 8360; 6300; 6400
Topology:
=========
.. ditaa::

+-------+                                    +-------+
|       |     +--------+      +--------+     |       |
|  hs1  <---->  ops1   <-----> ops2    <----->  hs2  |
|       |     +--------+      +--------+     |       |
+-------+                                    +-------+
"""

TOPOLOGY = """

# Nodes
[type=halon_0 name="OpenSwitch 1" target="true"] ops1
[type=halon_0 name="OpenSwitch 1" target="true"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 1"] hs2

# Links
hs1:eth1 -- ops1:if01
ops1:if02 -- ops2:if02
ops2:if01 -- hs2:eth1
"""

S1_IP = '10.0.0.1'
S2_IP = '10.0.0.2'
H1_IP = '11.0.0.1'
H2_IP = '11.0.0.2'
S1_LO_IP_1 = '1.1.1.1'
S2_LO_IP_1 = '2.2.2.2'
S1_LO_IP_2 = '3.3.3.3'
S2_LO_IP_2 = '4.4.4.4'
MASK = '24'
LO_MASK = '32'
VLAN = '10'
VNI = '1760'
TUN_NUM = '1'


@mark.timeout(1000)
def test_vxlan_basic(topology, step):
    """
    # Test ping between two hosts without VxLAN tunnel creation.
    # Test ping between two hosts connected through VxLAN tunnel.
    # Test ping between two hosts connected through VxLAN tunnel
      after both ip's on the switches have been updated.
    # Test ping between two hosts after the VxLAN tunnels on both
      switched have been deleted.

    Build a topology of two switches and two hosts and connect
    the hosts to the switches.
    Setup a VxLAN between switches and VLANs between ports
    and switches.
    Ping from host 1 to host 2.
    """

    s1 = topology.get('ops1')
    s2 = topology.get('ops2')
    h1 = topology.get('hs1')
    h2 = topology.get('hs2')

    assert s1 is not None, ("Unable to get switch 1 object - topology setup \
                            failed")
    assert s2 is not None, ("Unable to get switch 2 object - topology setup \
                            failed")
    assert h1 is not None, ("Unable to get host 1 object - topology setup \
                            failed")
    assert h2 is not None, ("Unable to get host 2 object - topology setup \
                            failed")

    """
    Step: Create the topology as shown and enable and configure all interfaces
    Result: Topology created successfulliy and all interfaces are enabled and
            configured
    """

    # Config vlan on switch 1
    with s1.libs.vtysh.ConfigVlan(VLAN) as ctx:
        ctx.no_shutdown()

    # Config Vlan on switch 2
    with s2.libs.vtysh.ConfigVlan(VLAN) as ctx:
        ctx.no_shutdown()

    # Config interface on switch 1
    with s1.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.no_routing()
        ctx.vlan_access(VLAN)
        ctx.no_shutdown()

    with s1.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.ip_address(S1_IP + '/' + MASK)
        ctx.no_shutdown()

    with s1.libs.vtysh.ConfigInterfaceLoopback('0') as ctx:
        ctx.ip_address(S1_LO_IP_1 + '/' + LO_MASK)

    with s1.libs.vtysh.ConfigInterfaceLoopback('1') as ctx:
        ctx.ip_address(S1_LO_IP_2 + '/' + LO_MASK)

    # Config interface on switch 2
    with s2.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.no_routing()
        ctx.vlan_access(VLAN)
        ctx.no_shutdown()

    with s2.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.ip_address(S2_IP + '/' + MASK)
        ctx.no_shutdown()

    with s2.libs.vtysh.ConfigInterfaceLoopback('0') as ctx:
        ctx.ip_address(S2_LO_IP_1 + '/' + LO_MASK)

    with s2.libs.vtysh.ConfigInterfaceLoopback('1') as ctx:
        ctx.ip_address(S2_LO_IP_2 + '/' + LO_MASK)

    """
    Step: Test ping between switch 1 and switch 2
    Result: Ping passed successfully
    """
    # Ping between the two switches
    step("##### Trying to ping between the two switches #####")
    switch_ping(s1, S2_IP, step)

    # Configure the hosts
    h1_ip_iface = H1_IP + '/24'
    h2_ip_iface = H2_IP + '/24'
    h1.libs.ip.interface('eth1', addr=h1_ip_iface, up=True)
    h2.libs.ip.interface('eth1', addr=h2_ip_iface, up=True)

    # Ping between the two switches
    step("##### Trying to ping between the VTEP IP addresses #####")
    with s1.libs.vtysh.Configure() as ctx:
        ctx.ip_route(S2_LO_IP_1 + '/' + LO_MASK, S2_IP)
        ctx.ip_route(S2_LO_IP_2 + '/' + LO_MASK, S2_IP)
    with s2.libs.vtysh.Configure() as ctx:
        ctx.ip_route(S1_LO_IP_1 + '/' + LO_MASK, S1_IP)
        ctx.ip_route(S1_LO_IP_2 + '/' + LO_MASK, S1_IP)

    switch_ping(s1, S2_LO_IP_1, step)
    switch_ping(s1, S2_LO_IP_2, step)

    """
    Step: Test ping between host 1 and host 2 without creation of VxLAN
          interface
    Result: Ping fails
    """
    # Negative test
    # Trying to ping without a VxLAN tunnel creation
    step("#### Trying to ping between two hosts without tunnel creation ####")
    host_negative_ping(h1, H2_IP, step)

    """
    Step: Create VxLAN interface interfaces on switch 1 and switch 2
    Result: VxLAN interface has been created successfully
    """
    # Configure tunnel interfaces on both the switches
    with s1.libs.vtysh.ConfigInterfaceVxlan(TUN_NUM) as ctx:
        ctx.source_ip(S1_LO_IP_1)
        ctx.no_shutdown()
    with s1.libs.vtysh.ConfigVni(TUN_NUM, VNI) as ctx:
        ctx.vtep_peer(S2_LO_IP_1)
        ctx.vlan(VLAN)

    with s2.libs.vtysh.ConfigInterfaceVxlan(TUN_NUM) as ctx:
        ctx.source_ip(S2_LO_IP_1)
        ctx.no_shutdown()
    with s2.libs.vtysh.ConfigVni(TUN_NUM, VNI) as ctx:
        ctx.vtep_peer(S1_LO_IP_1)
        ctx.vlan(VLAN)

    """
    Step: Test ping between host 1 and host 2 through the VxLAN interface
    Result: Ping passed successfully
    """
    # Trying to ping between the Host1 and Host2
    step("##### Trying to ping between the two hosts #####")
    host_ping(h1, H2_IP, step)

    """
    Step: Modify the source ip on both the switches
    Result: Modification of source ip done successfully
    """
    # Updating the tunnel's source IP address
    with s1.libs.vtysh.ConfigInterfaceVxlan(TUN_NUM) as ctx:
        ctx.source_ip(S1_LO_IP_2)

    step("#### Negative test-Trying to ping between two hosts with one\
         source IP updated ####")
    host_negative_ping(h1, H2_IP, step)

    with s1.libs.vtysh.ConfigVni(TUN_NUM, VNI) as ctx:
        ctx.vtep_peer(S2_LO_IP_2)

    with s2.libs.vtysh.ConfigInterfaceVxlan(TUN_NUM) as ctx:
        ctx.source_ip(S2_LO_IP_2)
    with s2.libs.vtysh.ConfigVni(TUN_NUM, VNI) as ctx:
        ctx.vtep_peer(S1_LO_IP_2)

    """
    Step: Test ping between host 1 and host 2 through the VxLAN interface
    Result: Ping passed successfully
    """
    # Trying to ping between the two switches after interface tunnel ip's
    # have been changed
    step("##### Trying to ping between the two hosts after both source IPs \
         have been updated #####")
    host_ping(h1, H2_IP, step)

    """
    Step: Delete the VxLAN interface from switch 1 and switch 2
    Result: VxLAN interface has been deleted from switch 1 and switch 2
    """
    # Deleting the tunnel from switch 1
    with s1.libs.vtysh.Configure() as ctx:
        ctx.no_interface_vxlan(TUN_NUM)

    # Deleting the tunnel from switch 2
    with s2.libs.vtysh.Configure() as ctx:
        ctx.no_interface_vxlan(TUN_NUM)

    """
    Step: Test ping between host 1 and host 2 after VxLAN interface has
          been deleted
    Result: Ping fails
    """
    # Trying to ping from Host 1 to Host 2 without tunnel in
    # Switch 1 and Switch 2, ping should fail.
    step("#### Trying to ping between two hosts after tunnel \
         deletion on both switches ####")
    host_negative_ping(h1, H2_IP, step)
