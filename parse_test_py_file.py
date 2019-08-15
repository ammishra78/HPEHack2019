#!/usr/bin/env python3
"""
Scripter: Jill McKay <jill.mckay@hpe.com>

Description: This script parses through and validates the formatting of a
        test_<DESCRIPTION>.py file. If there are any issues with the format
        of the test, the parser will throw the appropriate error.
"""

import os
import json
import sys
from argparse import ArgumentParser
from re import (
    DOTALL,
    IGNORECASE,
    search as re_search,
    finditer as re_finditer,
    findall as re_findall,
    sub as re_sub,
    match as re_match,
    split as re_split
)
from timeout import Timeout

WIKI = ('https://rndwiki.corp.hpecorp.net/confluence/display/hpnevpg/'
        '2.5.2+Test+Automation+Guidelines')
SUPPORTED_PLATFORMS = [
    '8320', '8320B', '8320C', '8320U', '8320X',
    '8325', '8325S', '8325W',
    '8360', 'KIDD',
    '8400', '8400DP', '8400VP', '8400HA', '8400-HA',
    '6300', '6300-VSF', '6300-STANDALONE',
    '6400', '6400HA',
    'Virtual-P4', 'Dr_Strange', 'Virtual-OVA',
    'arm-gns3', 'x86-gns3',
    'DOVA'
]
PLANNED_PRIORITIES = {
    '1': 'Low',
    '2': 'Medium',
    '3': 'High',
    '4': 'Urgent',
}
TEST_SUB_AREAS = ['Config-Persistence', 'Device-IOP', 'HA', 'Scalability',
                  'Soak', 'System Functional', 'System Stress', 'VSX-Sync',
                  'Supportability', 'VRF', 'VSX', 'VSF', 'REST', 'DRY-RUN',
                  'ANSIBLE', 'SNMP', 'WEB-UI']
TEST_CASE_ATTRIBUTES = ['CFD - Halon', 'CFD - PVOS', 'Cisco', 'Govt Cert-CC',
                        'Govt Cert-DoDIN', 'H3C', 'IFD -  PVOS', 'IFD - Halon',
                        'Leveraged from PVOS']
RELEASES_HALON = ['private', '10_00', '10_01', '10_02', '10_03', '10_04']
RELEASES_BOOMER = ['NetEdit_1.0', 'NetEdit_1.1', 'NetEdit_1.2', 'NetEdit_2.0']
ERROR_LIST = {}


def justify_tc_lines(unformatted_tc_text):
    formatted_lines = []

    for line in unformatted_tc_text.strip().splitlines():
        formatted_lines.append(line.strip())
    formatted_tc_text = "\n".join(formatted_lines)

    return formatted_tc_text


def assert_errors():
    """
    Print out the error list if can not continue with parser
    """

    errors = ERROR_LIST.items()
    assert not errors, (
        "{errors}\nRefer to WIKI for format: {wiki}".format(
            errors="\n".join([
                "{}: {}".format(ID, description) for ID, description in errors
            ]),
            wiki=WIKI
        )
    )
    # no errors to report
    return


def parse_test_header(file_contents):
    """
    This method parses just the test case header of the file.

    :param str file_contents: The file contents to be parsed
    :return dict: A dictionary containing the parsed information from the file
        in the form of:

    ::

        {
            'Author': {
                'name': 'Name LastName',
                'email': 'email@hpe.com'
            },
            'Scripter': {
                'name': 'Name LastName',
                'email': 'email@hpe.com'
            }
            'TestId': 0,
            'Release': '10_00'
            'TestName': 'Mirroring_LAG',
            'TestCaseAttributes': ''
            'SubArea': '',
            'Feature': 'Mirroring',
            'Objective': (
                'Verify mirroringfunctionality with LAG'
            ),
            'Requirements': (
                '    -2 Ridley switches\n'
                '    -3 traffic gen/analyzer ports\n'
                '    -1 IxNetwork capable host workstation'
            ),
            'TestDescription': (
                'Setup a mirroring session using LAG as the mirror source and '
                'destination and run traffic. Test using unicast, multicast, '
                'and broadcast traffic. Run multiple streams, varing mac '
                'source/dest addresses to load balance on the lag. Run mirror '
                'for egress only, ingress only, and both.'
            ),
            'PlanPriority': '3 - High',
            'TestPassCriteria': 'All steps pass'
            'PlatformIndepenent': 'N',
            'SupportedPlatforms': '8408ml;AS5712',
            'Topology': (
                '    +-------+       +-------+\n'
                '    |       |       |       |\n'
                '    |  ix1  |       |  ix2  |\n'
                '    |       |       |       |\n'
                '    +---+---+       +---+---+\n'
                '        |               |       +-------+\n'
                '        |               |       |  hs1  |\n'
                '    +---+---+ (lag) +---+---+   +-------+\n'
                '    |       |-------|       |\n'
                '    |  sw1  |       |  sw2  |\n'
                '    |       |-------|       |\n'
                '    +---+---+       +-------+\n'
                '        |\n'
                '        |\n'
                '    +---+---+\n'
                '    |       |\n'
                '    | ix3   |\n'
                '    |       |\n'
                '    +-------+'
            ),
            'TOPOLOGY': (
                'TOPOLOGY = \"\"\"\n'
                '# Nodes\n'
                '[type=halon_0 name="DUT" target="true"] sw1\n'
                '\"\"\"'
            )
        }
    """
    global ERROR_LIST

    test_file_format_re = (
        r'__doc__\s=\s\"\"\"\n(?P<tc_header>.*?)\n\s*\"\"\"'
        r'.*?'
        r'(?P<TOPO>TOPOLOGY\s=\s\"\"\"\n.*?target=\"true\".*?\n\s*\"\"\"\n?)'
    )

    author_re = (r':Author: (?P<name>[\w\- \.]+) [-=\|] '
                 r'(?P<email>\S+@hpe\.com) *\n')
    scripter_re = (r':Scripter: (?P<name>[\w\- ]+) [-=\|] '
                   r'(?P<email>\S+@hpe\.com) *\n')
    test_id_re = r':TestId: (?P<TestId>\d+|N/?A) *\n'
    release_re = r':Release: (?P<Release>\w+) *\n'
    test_name_re = r':TestName: +(?P<TestName>.*?)(?=\n:)'
    test_case_attrs_re = \
        r':TestCaseAttributes: +(?P<TestCaseAttributes>.+?)(?=\n:)'
    sub_area_re = r':SubArea: +(?P<SubArea>.+?)(?=\n:)'
    feature_re = r':Feature: +(?P<Feature>.*?)(?=\n:)'
    objective_re = r':Objective:\s*(?P<Objective>.*?)(?=\n:)'
    requirements_re = r':Requirements:\s*(?P<Requirements>.*?)(?=\n:)'
    test_description_re = r':TestDescription:\s*(?P<TestDescription>.*?)(?=\n:)'
    plan_priority_re = r':PlanPriority: +(?P<PlanPriority>\d ?- ?\w+\n)'
    test_pass_criteria_re = \
        r':TestPassCriteria:\s*(?P<TestPassCriteria>.*?)(?=\n:)'
    platform_independent_re = \
        r':PlatformIndependent: +(?P<PlatformIndependent>Y|N)\n'
    supported_platforms_re = \
        r':SupportedPlatforms: +(?P<SupportedPlatforms>.*?)\n'
    topology_re = r'Topology:\n=+\n\.\.\sditaa::\n(?P<Topology>.*)$'

    test_header_structure_re = (
        r':Author:.*'
        r'(:Scripter:.*)?'
        r':TestId:.*'
        r'(:Release:.*)?'
        r':TestName:.*'
        r'(:TestCaseAttributes:.*)?'
        r'(:SubArea:.*)?'
        r'(:Feature:.*)?'
        r':Objective:.*'
        r':Requirements:.*'
        r':TestDescription:.*'
        r':PlanPriority:.*'
        r':TestPassCriteria:.*'
        r':PlatformIndependent:.*'
        r':SupportedPlatforms:.*'
        r':?Topology:\s+=+\s+\.\.\sditaa::'
    )

    dict_test_case = {}

    # verifying basic components of test - header and TOPOLOGY string
    re_result = re_search(test_file_format_re, file_contents,
                          flags=(DOTALL | IGNORECASE))

    if not re_result:
        ERROR_LIST['TF01'] = (
            "File Test Case Header missing/improperly formatted AND/OR  "
            "TOPOLOGY string missing target=\"true\""
        )

        re_result = re_search(
            r'__doc__ = \"\"\"\n(?P<tc_header>.*?)\n\s*\"\"\"',
            file_contents, flags=DOTALL
        )

        if not re_result:
            ERROR_LIST['TF01'] = (
                "File Test Case Header missing"
            )
            assert_errors()
            return dict_test_case

    basic_components = re_result.groupdict()
    tc_header = basic_components.get("tc_header")
    dict_test_case['TOPOLOGY'] = basic_components.get("TOPO")

    # Validating Test Case Header Format
    re_result = re_search(author_re, tc_header, flags=(DOTALL | IGNORECASE))

    if not re_result:
        ERROR_LIST["TF02"] = (
            "Test Case Header Author field missing/improperly formatted"
        )
    else:
        dict_test_case['Author'] = re_result.groupdict()

    # grab scripter if it exists
    re_result = re_search(scripter_re, tc_header, flags=(DOTALL | IGNORECASE))
    if re_result:
        dict_test_case['Scripter'] = re_result.groupdict()
    else:
        dict_test_case['Scripter'] = None

    re_result = re_search(test_id_re, tc_header, flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF03"] = (
            "Test Case Header TestId field missing/improperly formatted. "
            "Expect a 4-digit ALM test case ID or 0000 if id "
            "is unknown/does not yet exist"
        )
    else:
        dict_test_case.update(re_result.groupdict())

    re_result = re_search(release_re, tc_header, flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF24"] = (
            "Test Case Header Release field missing/improperly formatted. "
        )
        dict_test_case['Release'] = ''
    else:
        dict_test_case.update(re_result.groupdict())

    re_result = re_search(test_name_re, tc_header, flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF04"] = (
            "Test Case Header TestName field missing/improperly formatted"
        )
    else:
        dict_test_case.update(re_result.groupdict())

    # grab TestCaseAttributes if it exists
    re_result = re_search(test_case_attrs_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if re_result:
        test_attrs = (re_result.group('TestCaseAttributes')
                               .strip("< >").rstrip(';'))
        test_attrs = [attr.strip() for attr in re_split(r',|;', test_attrs)]
        ERROR_LIST["TF26"] = ""
        for attr in test_attrs:
            if attr not in TEST_CASE_ATTRIBUTES:
                ERROR_LIST["TF26"] += ("TestCaseAttribute {} not in list of "
                                       "valid TestCaseAttributes: {}\n"
                                       .format(attr, TEST_CASE_ATTRIBUTES))
        # Clean up TF26 entries or remove key if no issues found
        if ERROR_LIST["TF26"]:
            ERROR_LIST["TF26"] = ERROR_LIST["TF26"].strip()
        else:
            del ERROR_LIST["TF26"]
        dict_test_case['TestCaseAttributes'] = ';'.join(test_attrs)
    else:
        dict_test_case['TestCaseAttributes'] = ''

    # grab sub_area if it exists
    re_result = re_search(sub_area_re, tc_header, flags=(DOTALL | IGNORECASE))
    if re_result:
        sub_areas = re_result.group('SubArea').strip("< >").rstrip(';')
        sub_areas = [area.strip() for area in re_split(r',|;', sub_areas)]
        ERROR_LIST["TF25"] = ""
        for sub_area in sub_areas:
            if sub_area not in TEST_SUB_AREAS:
                ERROR_LIST["TF25"] += (
                    "SubArea {} not in list of valid TestSubAreas: {}\n"
                    .format(sub_area, TEST_SUB_AREAS)
                )
        # Clean up TF25 entries or remove key if no issues found
        if ERROR_LIST["TF25"]:
            ERROR_LIST["TF25"] = ERROR_LIST["TF25"].strip()
        else:
            del ERROR_LIST["TF25"]
        dict_test_case['SubArea'] = ';'.join(sub_areas)
    else:
        dict_test_case['SubArea'] = ''

    # grab feature if it exists
    re_result = re_search(feature_re, tc_header, flags=(DOTALL | IGNORECASE))
    if re_result:
        dict_test_case.update(re_result.groupdict())
    else:
        dict_test_case['Feature'] = ''

    re_result = re_search(objective_re, tc_header, flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF05"] = (
            "Test Case Header Objective field missing/improperly formatted"
        )
    else:
        dict_test_case['Objective'] = re_sub(
            r'\n\s*', ' ', re_result.group('Objective')
        ).strip()

    re_result = re_search(requirements_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF06"] = (
            "Test Case Header Requirements field missing/improperly formatted"
        )
    else:
        dict_test_case['Requirements'] = (
            re_result.group('Requirements').strip()
        )

    re_result = re_search(test_description_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF07"] = (
            "Test Case Header TestDescription field missing/improperly "
            "formatted"
        )
    else:
        dict_test_case['TestDescription'] = re_sub(
            r'\n\s*', ' ', re_result.group('TestDescription')
        ).strip()

    re_result = re_search(plan_priority_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF08"] = (
            "Test Case Header PlanPriority field missing/improperly formatted"
        )
    else:
        plan_pri = re_result.group('PlanPriority')
        plan_pri_num, plan_pri_val = plan_pri.split('-')
        plan_pri_num = plan_pri_num.strip()
        plan_pri_val = plan_pri_val.strip()
        if PLANNED_PRIORITIES.get(plan_pri_num, None) != plan_pri_val:
            ERROR_LIST["TF08"] = (
                "Test Case Header PlanPriority field missing/improperly "
                "formatted"
            )
        else:
            dict_test_case['PlanPriority'] = "{num} - {val}".format(
                num=plan_pri_num, val=plan_pri_val
            )

    re_result = re_search(test_pass_criteria_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF09"] = (
            "Test Case Header TestPassCriteria field missing/improperly "
            "formatted"
        )
    else:
        dict_test_case['TestPassCriteria'] = re_sub(
            r'\n\s*', ' ', re_result.group('TestPassCriteria')
        ).strip()

    re_result = re_search(platform_independent_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF10"] = (
            "Test Case Header PlatformIndependent field missing/improperly "
            "formatted"
        )
    else:
        dict_test_case.update(re_result.groupdict())

    re_result = re_search(supported_platforms_re, tc_header,
                          flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF11"] = (
            "Test Case Header SupportedPlatforms field missing/improperly "
            "formatted"
        )
    else:
        dict_test_case.update(re_result.groupdict())
    # validate supported platforms listed
    platforms = re_findall(r'[\w-]+',
                           dict_test_case.get('SupportedPlatforms', ''))
    ERROR_LIST["TF12"] = ""
    for platform in platforms:
        if platform.strip() not in SUPPORTED_PLATFORMS:
            ERROR_LIST["TF12"] += (
                "Platform {} not in list of Supported Platforms: {}\n"
            ).format(platform.strip(), SUPPORTED_PLATFORMS)
    # Clean up TF12 entries or remove key if no issues found
    if ERROR_LIST["TF12"]:
        ERROR_LIST["TF12"] = ERROR_LIST["TF12"].strip()
    else:
        del ERROR_LIST["TF12"]
    dict_test_case['SupportedPlatforms'] = ';'.join(platforms)

    re_result = re_search(topology_re, tc_header, flags=(DOTALL | IGNORECASE))
    if not re_result:
        ERROR_LIST["TF13"] = (
            "Test Case Header topology field missing/improperly formatted"
        )
    else:
        dict_test_case.update(re_result.groupdict())

    # Validate that test case header fields in proper order
    if not re_search(test_header_structure_re, tc_header,
                     flags=(DOTALL | IGNORECASE)):
        ERROR_LIST["TF14"] = (
            "Test Case Header formatted incorrectly, required fields may be "
            "in the wrong order"
        )

    return dict_test_case


def parse_test_step(re_step, test_name, step_count):
    global ERROR_LIST

    step = re_step.groupdict()
    step['name'] = "{test_name}_{step_id}".format(
        test_name=test_name,
        step_id=step_count
    )
    step['description'] = justify_tc_lines(step['description'])

    if not step['result']:
        ERROR_LIST["TF18"] += (
            "Step '{}' missing result\n"
        ).format(step['description'].strip())
    else:
        step['result'] = justify_tc_lines(step['result'])

    return step


def get_referenced_file_path(test_dir, file_path):
    if file_path.startswith("topology_common"):
        return os.path.join(test_dir.rsplit('/tests/')[0],
                            'libraries/hpe_topology_common/lib', file_path)
    else:  # treat as relative path
        return os.path.abspath(os.path.join(test_dir, file_path))


def parse_test_steps(contents, test_steps, test_name, dict_test_case,
                     test_dir):
    global ERROR_LIST

    test_steps_re = (
        r'("|\'){3}\s*(?:Step:|STEP:|\s+\d+\.)\s*(?P<description>.*?)'
        r'(?:(?:Result:|RESULT:)\s*(?P<result>.*?)|)("|\'){3}'
    )

    function_re = (
        r'def\s{}\(.*?\):(?:\s+#\snoqa)?\n'
        r'(?P<test_case>.*?)(?=def\s|$)'
    )

    # collect all test steps
    re_steps = re_finditer(test_steps_re, contents, flags=DOTALL)
    step_count = 1

    for re_step in re_steps:
        step = parse_test_step(re_step, test_name, step_count)

        # check for stub
        if not dict_test_case['contains_stub'] and \
                step['description'].lower() == "stub test step":
            dict_test_case['contains_stub'] = True

        re_result = re_match(r'<(\S+)>', step['description'])
        if re_result is not None:
            func_name = re_result.group(1)
            file = get_referenced_file_path(test_dir, step['result'])

            if os.path.exists(file) and os.path.isfile(file):
                with open(file, 'r') as file_pointer:
                    contents = file_pointer.read()

                re_result = re_findall(function_re.format(func_name), contents,
                                       flags=DOTALL)

                if re_result:
                    func_contents = re_result[0]
                    sub_step_name = "{} {} {}".format(test_name,
                                                      step_count, func_name)
                    parse_test_steps(func_contents, test_steps, sub_step_name,
                                     dict_test_case, test_dir)
                else:
                    ERROR_LIST["TF23"] = ("Referenced function {} does not "
                                          "exist!".format(func_name))

            else:
                ERROR_LIST["TF22"] = ("Referenced file {} does not "
                                      "exist!".format(file))
        else:
            test_steps.append(step)

        step_count += 1


def parse_test_file(file_contents, file_dir):
    """
    This method parses through the test file to make sure that the file is
    formatted correctly and contains all of the necessary information for
    generating/updating an MD document or ALM test case.

    :param str file_contents: The file contents to be parsed
    :param str file_dir: the directory where the test file lives
    :return dict: A dictionary containing the parsed information from the file
        in the form of:

    ::

        {
            'Author': {
                'name': 'Name LastName',
                'email': 'email@hpe.com'
            },
            'Scripter': None,
            'TestId': 0,
            'Release': '',
            'TestName': 'Mirroring_LAG',
            'TestAttributes': '',
            'SubArea': '',
            'Feature': '',
            'Objective': (
                'Verify mirroringfunctionality with LAG'
            ),
            'Requirements': (
                '    -2 Ridley switches\n'
                '    -3 traffic gen/analyzer ports\n'
                '    -1 IxNetwork capable host workstation'
            ),
            'TestDescription': (
                'Setup a mirroring session using LAG as the mirror source and '
                'destination and run traffic. Test using unicast, multicast, '
                'and broadcast traffic. Run multiple streams, varing mac '
                'source/dest addresses to load balance on the lag. Run mirror '
                'for egress only, ingress only, and both.'
            ),
            'PlanPriority': '3 - High',
            'TestPassCriteria': 'All steps pass'
            'PlatformIndependent': 'N',
            'SupportedPlatforms': '8408ml;AS5712',
            'Topology': (
                '    +-------+       +-------+\n'
                '    |       |       |       |\n'
                '    |  ix1  |       |  ix2  |\n'
                '    |       |       |       |\n'
                '    +---+---+       +---+---+\n'
                '        |               |       +-------+\n'
                '        |               |       |  hs1  |\n'
                '    +---+---+ (lag) +---+---+   +-------+\n'
                '    |       |-------|       |\n'
                '    |  sw1  |       |  sw2  |\n'
                '    |       |-------|       |\n'
                '    +---+---+       +-------+\n'
                '        |\n'
                '        |\n'
                '    +---+---+\n'
                '    |       |\n'
                '    | ix3   |\n'
                '    |       |\n'
                '    +-------+'
            ),
            'TOPOLOGY': ,
            'Steps': [
                {
                    'name': 'mirroring_lag_configure_1',
                    'description': 'config vlan 100 on sw1 and sw2',
                    'result': 'vlans configured'
                },
                ...
                {
                    'name': 'mirroring_lag_rx_broadcast_traffic_1',
                    'description': (
                        'configure a mirror session on switch 1 to '
                        'capture RX traffic'
                    ),
                    'result': (
                        'sw1 if01 source port, lag interface is dest, '
                        'mirror configured'
                    )
                },
            ],
            'test_marks': {},
            'automated': "Yes",
            'test_suited_for_ostl': True,
            'crs_referenced': [],
            'contains_stub': False,
        }
    """
    global ERROR_LIST

    # Make sure error list is empty
    ERROR_LIST = {}

    test_func_re = (
        r'(?P<test_marks>(?:@(?:pytest\.)?mark\.[^\n]+\s*)+)?\n'
        r'def (?P<test_func>test_[^\(]+)\([^\)]*\):\s+'
        r'(?P<test_case>.+?)(?=\n@|\ndef |$)'
    )

    env_setup_re = (
        r'def env_setup\(.*?\):(?: +# noqa)?\n'
        r'(?P<test_case>.*?)(?=def |$)'
    )

    skip_marks_re = [
        r'mark\.skip\((?:reason=|)[\"\'](In Progress|Dev Funnel)[\'\"]\)',
        r'mark\.skip\((?:reason=|)[\"\']Not Feasible[\'\"]\)',
        r'mark\.skip\((?:reason=|)[\"\'].*[\'\"]\)'
    ]

    platform_incompatible_marks_re = (
        r'mark\.platform_incompatible\(\[\'ostl\'\]\)'
    )

    dos_line_endings_re = r'\r\n'
    if re_search(dos_line_endings_re, file_contents):
        ERROR_LIST["TF20"] = (
            "File using DOS line endings, expected UNIX line endings"
        )
        # switch to unix line endings so rest of parser can run
        file_contents = re_sub(dos_line_endings_re, "\n", file_contents)

    dict_test_case = {}
    dict_test_case['contains_stub'] = False
    dict_test_case.update(parse_test_header(file_contents))

    stubbed_keys = ['Objective', 'Requirements', 'TestPassCriteria']
    for key in stubbed_keys:
        if key in dict_test_case and dict_test_case[key].lower() == "stub":
            dict_test_case['contains_stub'] = True

    test_steps = []

    max_num_env_setup = 1
    re_result = re_findall(env_setup_re, file_contents, flags=DOTALL)
    if len(re_result) > max_num_env_setup:
        ERROR_LIST["TF21"] = "There are too many declarations of env_setup"

    if re_result:
        test_case = re_result[0]
        test_name = "env_setup"

        ERROR_LIST["TF18"] = ""

        # collect all test steps
        parse_test_steps(test_case, test_steps, test_name, dict_test_case,
                         file_dir)

        if ERROR_LIST["TF18"]:
            ERROR_LIST["TF18"] = ERROR_LIST["TF18"].strip()
        else:
            del ERROR_LIST["TF18"]

    re_result = re_findall(r'def test_', file_contents)
    if not re_result:
        ERROR_LIST["TF15"] = "Unable to find any test_ functions"
        assert_errors()

    num_test_expected = len(re_result)

    re_result = re_findall(
        r'def test_(?P<test_func>\S+)\(.*?\)',
        file_contents, flags=DOTALL
    )
    if not re_result:
        ERROR_LIST["TF16"] = "Unable to find any valid test_ functions"
        assert_errors()

    re_results = re_finditer(test_func_re, file_contents, flags=DOTALL)
    if not re_results:
        ERROR_LIST["TF16"] = "Unable to find any valid test_ functions"
        assert_errors()

    num_test_found = 0
    for re_result in re_results:
        num_test_found += 1
        partial = re_result.groupdict()
        # get test step name
        test_name = partial['test_func']
        test_marks = partial['test_marks']

        if "TF18" not in ERROR_LIST.keys():
            ERROR_LIST["TF18"] = ""

        # collect all test steps
        parse_test_steps(partial['test_case'], test_steps, test_name,
                         dict_test_case, file_dir)
        if not test_steps:
            ERROR_LIST["TF17"] = (
                "Test function {} does not contain any valid STEP strings"
            ).format(test_name)

        if ERROR_LIST["TF18"]:
            ERROR_LIST["TF18"] = ERROR_LIST["TF18"].strip()
        else:
            del ERROR_LIST["TF18"]

        if 'test_marks' not in dict_test_case:
            dict_test_case['test_marks'] = {}
        if test_marks:
            dict_test_case['test_marks'][test_name] = \
                ';'.join(test_marks.split('\n'))

        if 'test_funcs' not in dict_test_case:
            dict_test_case['test_funcs'] = []
        dict_test_case['test_funcs'].append(test_name)

        # look at pytest marks for skip markers
        if (
            test_marks and
            re_search(skip_marks_re[0], test_marks)
        ):
            # skip marker found for "In Progress"
            if 'automated' not in dict_test_case:
                dict_test_case['automated'] = "Dev Funnel"
        elif (
            test_marks and
            re_search(skip_marks_re[1], test_marks)
        ):
            # skip marker found for "Not Feasible"
            if 'automated' not in dict_test_case:
                dict_test_case['automated'] = "Not Feasible"
        else:
            # no skip marker found, at least 1 test step automated
            dict_test_case['automated'] = "Yes"
        # look at pytest marks for platform incompatible markers
        if (
            test_marks and
            re_search(platform_incompatible_marks_re, test_marks)
        ):
            # platform incompatible marker found,at least 1 test step
            # not compatible with OSTL
            dict_test_case['test_suited_for_ostl'] = 'N'
        else:
            # no marker found
            if 'test_suited_for_ostl' not in dict_test_case:
                dict_test_case['test_suited_for_ostl'] = 'Y'

    if num_test_found != num_test_expected:
        ERROR_LIST["TF19"] = (
            "Found {} valid test_ functions. Expected {}."
        ).format(num_test_found, num_test_expected)
    dict_test_case['Steps'] = test_steps

    # Search the file for any references to CRs
    dict_test_case['crs_referenced'] = []
    cr_re = r'CR\s*\d{4,}'
    re_results = re_finditer(cr_re, file_contents, flags=IGNORECASE)
    for re_result in re_results:
        cr = re_sub(r'\s+', '', re_result.group(0)).upper()  # make form CR####
        if cr not in dict_test_case['crs_referenced']:
            dict_test_case['crs_referenced'].append(cr)

    assert_errors()
    return dict_test_case


def test_script(test_script):
    if os.path.exists(test_script) and os.path.isfile(test_script):
        file = os.path.basename(test_script)
        if file.startswith("test_") and file.endswith(".py"):
            return test_script
    else:
        raise ValueError("test_script must be a valid python file that starts"
                         " with test_ and ends with .py")


def output_format(output_format):
    supported_formats = ['json', 'csv']
    if output_format.lower() in supported_formats:
        return output_format.lower()
    else:
        raise ValueError("format not in supported formats: {}"
                         .format(supported_formats))


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

    with Timeout(20):
        output = parse_test_file(test_contents, os.path.dirname(test_script))
        if out_fmt.lower() == 'json':
            print(json.dumps(output, sort_keys=True, indent=4,
                             separators=(',', ': ')))
        elif out_fmt.lower() == 'csv':
            separator = '~'
            for def_test in output['test_funcs']:
                print(separator.join([
                    rel_path,
                    def_test,
                    '{name} - {email}'.format(**output['Author']),
                    output['TestId'],
                    output['Release'],
                    output['TestName'],
                    # repr(string)[1:-1] = raw version of string and strip ''
                    repr(output['Objective'])[1:-1],
                    repr(output['Requirements'])[1:-1],
                    repr(output['TestDescription'])[1:-1],
                    output['PlanPriority'],
                    output['TestPassCriteria'],
                    output['PlatformIndependent'],
                    output['SubArea'],
                    output['SupportedPlatforms'],
                    output['test_marks'].get(def_test, ''),
                    repr(output['Topology'])[1:-1]
                ]))
            pass


# If someone runs this as a standalone python script
if __name__ == "__main__":
    main(sys.argv[1:])
