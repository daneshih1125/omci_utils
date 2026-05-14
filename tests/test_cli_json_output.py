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

    yield

    test_files = [
        "omcicheck_example.pcap",
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
