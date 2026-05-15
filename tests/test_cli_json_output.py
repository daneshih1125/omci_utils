#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih daneshih1125@gmail.com
# Licensed under the MIT License.
#
import subprocess
import pytest
import json
import os


@pytest.fixture(scope="module", autouse=True)
def setup_test_files():

    subprocess.run(["python3", "utils/generate_omcicheck_example.py"], check=True)
    subprocess.run(["python3", "utils/generate_dual_gem_shared_tcont.py"], check=True)

    yield

    test_files = [
        "omcicheck_example.pcap",
        "single_unit_1_tont_2_gem.pcap",
    ]

    for f in test_files:
        if os.path.exists(f):
            os.remove(f)


def test_cmd_check_json_output():

    result = subprocess.run(
        [
            "omcipcap",
            "check",
            "--json-output",
            "examples/omcicheck_example.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    #
    # verify stdout is valid json
    #
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    #
    # verify top-level structure
    #
    assert "packets" in output, "Missing 'packets' field in json output"

    assert "summary" in output, "Missing 'summary' field in json output"

    packets = output["packets"]
    summary = output["summary"]

    #
    # verify summary counters
    #
    assert summary["resp_fail_count"] == 2, "Should detect 2 OMCI response failures"

    assert summary["is_vendor_me_count"] == 5, (
        "Should detect 5 vendor/future ME packets"
    )

    assert summary["resp_late_count"] == 1, "Should detect 1 late OMCI response"

    assert summary["transaction_id_duplicate_count"] == 1, (
        "Should detect 1 duplicate transaction ID"
    )

    #
    # verify exported abnormal packet count
    #
    assert len(packets) == 8, "Expected 8 abnormal packets in json output"

    #
    # verify INSTANCE_EXISTS response exported correctly
    #
    instance_exists_pkt = next((pkt for pkt in packets if pkt["packet_no"] == 58), None)

    assert instance_exists_pkt is not None, "INSTANCE_EXISTS packet not found"

    assert instance_exists_pkt["action"] == "CREATE"

    assert instance_exists_pkt["me_class"] == 84

    assert instance_exists_pkt["result"]["success"] is False

    assert instance_exists_pkt["result"]["text"] == ("Err: INSTANCE_EXISTS")

    #
    # verify UNKNOWN_ME response exported correctly
    #
    unknown_me_pkt = next((pkt for pkt in packets if pkt["packet_no"] == 60), None)

    assert unknown_me_pkt is not None, "UNKNOWN_ME packet not found"

    assert unknown_me_pkt["action"] == "SET"

    assert unknown_me_pkt["me_class"] == 241

    assert unknown_me_pkt["result"]["success"] is False

    assert unknown_me_pkt["result"]["text"] == ("Err: UNKNOWN_ME")

    #
    # verify late response packet exported correctly
    #
    late_response_pkt = next(
        (pkt for pkt in packets if pkt["status"] == "[LATE]"), None
    )

    assert late_response_pkt is not None, "Late response packet not found"

    assert late_response_pkt["action"] == "GET"

    assert late_response_pkt["me_name"] == "ONT2-G"

    assert late_response_pkt["result"]["success"] is True

    #
    # verify duplicate transaction ID packet exported correctly
    #
    tid_duplicate_pkt = next(
        (pkt for pkt in packets if pkt["status"] == "[TID_DUPLICATE]"), None
    )

    assert tid_duplicate_pkt is not None, "Duplicate transaction ID packet not found"

    assert tid_duplicate_pkt["transaction_id"] == 32

    assert tid_duplicate_pkt["from_olt"] is True

    #
    # verify vendor/future ME packets exported correctly
    #
    vendor_me_classes = {
        pkt["me_class"]
        for pkt in packets
        if "vendor" in pkt["me_name"].lower() or "future" in pkt["me_name"].lower()
    }

    assert vendor_me_classes == {241, 350, 500}, "Vendor/Future ME classes mismatch"


def test_cmd_vlan_json_output():
    """
    Verify 'omcipcap vlan_tbl --json-output' produces valid JSON and
    correctly parses VLAN tagging operation rules (ME 171).
    """
    result = subprocess.run(
        [
            "omcipcap",
            "vlan_tbl",
            "--json-output",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    assert isinstance(output, list), "VLAN JSON output should be a list"
    assert len(output) > 0, "No VLAN instances found in output"

    vlan_inst = output[0]
    required_keys = ["inst_id", "rules", "assoc_ptr", "assoc_type", "ds_mode"]
    for key in required_keys:
        assert key in vlan_inst, f"Missing '{key}' field in VLAN JSON output"

    assert vlan_inst["inst_id"] == 1, "incorrect VLAN instance ID"
    assert vlan_inst["assoc_ptr"] == 257, "incorrect Associated ME pointer"
    assert vlan_inst["assoc_type"] == "Physical path termination point Ethernet UNI", (
        "incorrect Associated ME pointer"
    )
    assert vlan_inst["ds_mode"][:7] == "Inverse", "incorrect Associated Downstream Mode"

    rules = vlan_inst["rules"]
    assert isinstance(rules, list), "'rules' should be a list"
    assert len(rules) == 4, "Should get 4 VLAN rules"

    rule_0 = rules[0]
    assert rule_0["action_type"] == "Single Default: Discard", (
        "Rule 0 Action Type not match"
    )

    expected_r0_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 14,
        "f_in_vid": 4096,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 3,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 15,
        "t_in_vid": 0,
        "t_in_tpid": 0,
    }

    assert rule_0["data"] == expected_r0_data, "Rule 0 data dictionary mismatch"

    rule_1 = rules[1]
    assert rule_1["action_type"] == "Double Default: Discard", (
        "Rule 1 Action Type not match"
    )

    expected_r1_data = {
        "f_out_prio": 14,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 14,
        "f_in_vid": 4096,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 3,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 15,
        "t_in_vid": 0,
        "t_in_tpid": 0,
    }

    assert rule_1["data"] == expected_r1_data, "Rule 1 data dictionary mismatch"

    rule_2 = rules[2]
    assert (
        rule_2["action_type"] == "Single: Modify tag, keep prio  C(100)-F -> X(100)-F"
    ), "Rule 2 Action Type not match"

    expected_r2_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 8,
        "f_in_vid": 100,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 1,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 8,
        "t_in_vid": 100,
        "t_in_tpid": 0,
    }

    assert rule_2["data"] == expected_r2_data, "Rule 2 data dictionary mismatch"

    rule_3 = rules[3]
    assert (
        rule_3["action_type"] == "Single: Modify tag, keep prio  C(200)-F -> X(200)-F"
    ), "Rule 3 Action Type not match"

    expected_r3_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 8,
        "f_in_vid": 200,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 1,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 8,
        "t_in_vid": 200,
        "t_in_tpid": 0,
    }

    assert rule_3["data"] == expected_r3_data, "Rule 3 data dictionary mismatch"
