#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import subprocess
import pytest
import json
import os


@pytest.fixture(scope="module", autouse=True)
def setup_test_files():
    """
    Generate the test pcap file using the utility script.
    """
    subprocess.run(["python3", "utils/generate_dual_gem_shared_tcont.py"], check=True)
    yield
    # Cleanup
    if os.path.exists("single_unit_1_tont_2_gem.pcap"):
        os.remove("single_unit_1_tont_2_gem.pcap")


def get_topology_json():
    """
    Helper to run the topology command and return parsed JSON.
    """
    cmd = ["omcipcap", "topology", "-j", "single_unit_1_tont_2_gem.pcap"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail("Failed to parse JSON output from topology command")


def test_nodes_semantic_integrity():
    """
    Verify that nodes contain correct semantic data and standardized IDs.
    """
    data = get_topology_json()
    nodes = {n["id"]: n for n in data["nodes"]}

    # 1. Verify T-CONT (262) node and its specific attributes
    tcont_id = "262_32768"
    assert tcont_id in nodes, f"Node {tcont_id} (T-CONT) not found in output"
    tcont = nodes[tcont_id]
    assert tcont["class_id"] == 262, "Incorrect class_id for T-CONT"
    assert tcont["attributes"]["Alloc-ID"] == 1000, (
        "Alloc-ID mismatch in T-CONT attributes"
    )

    # 2. Verify PPTP Ethernet UNI (11) node
    uni_id = "11_257"
    assert uni_id in nodes, f"Node {uni_id} (UNI) not found in output"
    assert nodes[uni_id]["name"] == "PPTP_ETHERNET_UNI", "Incorrect name for PPTP node"
    pptp_attrs = nodes[uni_id]["attributes"]
    assert pptp_attrs["Expected Type"] == 49, "Incorrect Tyoe for PPTP node"

    # 3. Verify Extended VLAN Tagging (171) semantic translation
    vlan_id = "171_1"
    assert vlan_id in nodes, f"Node {vlan_id}  not found"
    vlan_attrs = nodes[vlan_id]["attributes"]
    assert vlan_attrs["Associated ME pointer"] == 257, "Associated ME pointer mismatch"

    # 4. Mac Bridge Service Profile
    br_srv_id = "45_1"
    assert br_srv_id in nodes, f"Node {br_srv_id}  not found"

    # 5. Mac Bridge Port configure data inst 1
    brport_id_1 = "47_1"
    assert brport_id_1 in nodes, f"Node {brport_id_1}  not found"

    # 6. GEM PORT NETWORK CTP inst 1
    ctp_1 = "268_1"
    assert ctp_1 in nodes, f"Node {ctp_1}  not found"

    # 7. GEM PORT NETWORK CTP inst 2
    ctp_2 = "268_2"
    assert ctp_2 in nodes, f"Node {ctp_2}  not found"

    # 8. 8021p inst 1
    dop1p_1 = "130_1"
    assert dop1p_1 in nodes, f"Node {dop1p_1}  not found"

    # 9.  Mac Bridge Port configure data inst 2
    brport_id_2 = "47_2"
    assert brport_id_2 in nodes, f"Node {brport_id_2}  not found"

    # 10. GEM INTERWORKING_TERMINATION POINT inst 1
    inter_1 = "266_1"
    assert inter_1 in nodes, f"Node {inter_1}  not found"

    # 11. VLAN filter
    filter_2 = "84_2"
    assert filter_2 in nodes, f"Node {filter_2}  not found"

    # 12. 8021p inst 2
    dop1p_2 = "130_2"
    assert dop1p_2 in nodes, f"Node {dop1p_2}  not found"

    # 13.  Mac Bridge Port configure data inst 2
    brport_id_3 = "47_3"
    assert brport_id_3 in nodes, f"Node {brport_id_3}  not found"

    # 14. GEM INTERWORKING_TERMINATION POINT inst 2
    inter_2 = "266_2"
    assert inter_2 in nodes, f"Node {inter_2}  not found"

    # 15. VLAN filter
    filter_3 = "84_3"
    assert filter_3 in nodes, f"Node {filter_3}  not found"


def test_edges_logic_and_semantic_relations():
    """
    Detailed verification of edges including both human labels and AI relations.
    """
    data = get_topology_json()
    edges = data["edges"]

    def find_edge(source, target):
        return next(
            (e for e in edges if e["source"] == source and e["target"] == target), None
        )

    # 1. VLAN OP 171_1 -> UNI 11_257
    e1 = find_edge("171_1", "11_257")
    assert e1 is not None, "Edge VLAN OP (171_1) to UNI (11_257) is missing"
    assert e1["relation"] == "vlan_op_associated_with_me", (
        "Relation mismatch: VLAN OP to UNI"
    )
    assert e1["label"] == "assoc_ptr", "Label mismatch: assoc_ptr for VLAN OP"

    # 2. Bridge Port 47_1 -> Bridge Profile 45_1
    e2 = find_edge("47_1", "45_1")
    assert e2 is not None, "Edge Bridge Port (47_1) to Profile (45_1) is missing"
    assert e2["relation"] == "belongs_to_bridge", "Relation mismatch: bridge_ptr"

    assert e2["label"] == "bridge_ptr", (
        "Label mismatch: belongs_to_bridge for Bridge Profile"
    )

    # 3. Bridge Port 47_1 -> UNI 11_257 (TP Pointer)
    e3 = find_edge("47_1", "11_257")
    assert e3 is not None, (
        "Edge Bridge Port (47_1) to UNI (11_257) via tp_ptr is missing"
    )
    assert e3["relation"] == "points_to_transport_termination", (
        "Relation mismatch: tp_ptr to UNI"
    )
    assert e3["label"] == "tp_ptr", "Label mismatch: TP pointer of Bridge Port"

    # 4. GEM Port 268_1 -> T-CONT 262_32768
    e4 = find_edge("268_1", "262_32768")
    assert e4 is not None, "Edge GEM Port (268_1) to T-CONT (262_32768) is missing"
    assert e4["relation"] == "traffic_mapped_to_tcont", (
        "relation mismatch: traffic_mapped_to_tcont"
    )
    assert e4["label"] == "tcont_ptr", "Label mismatch: T-CONT pointer of GEM port"

    # 5. GEM Port 268_2 -> T-CONT 262_32768 (Shared T-CONT validation)
    # Checks if multiple GEM ports can correctly link to a single upstream T-CONT
    e5 = find_edge("268_2", "262_32768")
    assert e5 is not None, (
        "Edge from secondary GEM (268_2) to shared T-CONT (262_32768) is missing"
    )
    assert e5["relation"] == "traffic_mapped_to_tcont", (
        f"Incorrect AI relation for edge 268_2->262_32768: {e5.get('relation')}"
    )
    assert e5["label"] == "tcont_ptr", "Label mismatch: T-CONT pointer of GEM port"

    # 6. Bridge Port 47_2 -> Bridge Profile 45_1
    # Validates that the second port points to the correct bridge service profile
    e6 = find_edge("47_2", "45_1")
    assert e6 is not None, "Edge from Bridge Port (47_2) to Profile (45_1) is missing"
    assert e6["relation"] == "belongs_to_bridge", (
        f"Incorrect relation for bridge_ptr: {e6.get('relation')}"
    )
    assert e6["label"] == "bridge_ptr", "Label mismatch: Bridge pointer of Bridge Port"

    # 7. Bridge Port 47_2 -> Dot1p Mapper 130_1
    # Tests the TP pointer link from Bridge Port to the 802.1p Mapper
    e7 = find_edge("47_2", "130_1")
    assert e7 is not None, (
        "Edge from Bridge Port (47_2) to Dot1p Mapper (130_1) is missing"
    )
    assert e7["relation"] == "points_to_transport_termination", (
        "Relation mismatch: tp_ptr from 47_2 should point to transport termination"
    )
    assert e7["label"] == "tp_ptr", "Label mismatch: TP pointer of Bridge Port"

    # 8. GEM IWTP 266_1 -> GEM Port 268_1
    # Verifies the internal mapping between Interworking TP and the GEM Port CTP
    e8 = find_edge("266_1", "268_1")
    assert e8 is not None, "Edge from GEM IWTP (266_1) to GEM Port (268_1) is missing"
    assert e8["label"] == "gem_ptr", "Label 'gem_ptr' missing for edge 266_1->268_1"
    assert e8["relation"] == "iw_linked_to_gem_port", (
        "relation mismatch for GEM IWTP to GEM Port link"
    )
    assert e8["label"] == "gem_ptr", "Label mismatch: GEM pointer of IWTP"

    # 9. GEM IWTP 266_1 -> Dot1p Mapper 130_1
    # Verify service profile mapping (srv_ptr) based on interworking option
    e9 = find_edge("266_1", "130_1")
    assert e9 is not None, (
        "Edge from GEM IWTP (266_1) to Service Profile (130_1) is missing"
    )
    assert e9["relation"] == "service_profile_mapping", (
        "Relation mismatch: expected service_profile_mapping"
    )
    assert e9["label"] == "srv_ptr", "Label mismatch: Bridge Service pointer of IWTP"

    # 10. VLAN Filter 84_2 -> Bridge Port 47_2 (Implicit Match)
    # Crucial test for the AI-Ready implicit matching logic for VLAN filters
    e10 = find_edge("84_2", "47_2")
    assert e10 is not None, (
        "Implicit edge from VLAN Filter (84_2) to Port (47_2) is missing"
    )
    assert e10["relation"] == "vlan_filter_bind_to_port", (
        "relation mismatch: should indicate vlan filter binding"
    )
    assert e10["label"] == "Filter-on", "Label mismatch: expected 'Filter-on' for ME 84"

    # 11. Bridge Port 47_3 -> Bridge Profile 45_1
    # Verify that the third port also correctly points to the shared bridge profile
    e11 = find_edge("47_3", "45_1")
    assert e11 is not None, "Edge from Bridge Port (47_3) to Profile (45_1) is missing"
    assert e11["relation"] == "belongs_to_bridge", (
        "relation mismatch: should indicate belongs_to_bridge"
    )
    assert e11["label"] == "bridge_ptr", "Label 'bridge_ptr' missing for the third port"

    # 12. Bridge Port 47_3 -> Dot1p Mapper 130_2
    # Verify the third bridge port points to its specific mapper instance
    e12 = find_edge("47_3", "130_2")
    assert e12 is not None, (
        "Edge from Bridge Port (47_3) to Dot1p Mapper (130_2) is missing"
    )
    assert e12["relation"] == "points_to_transport_termination", (
        "Relation mismatch: tp_ptr from 47_3 should point to its termination mapper"
    )
    assert e12["label"] == "tp_ptr", "Label mismatch: TP pointer of Bridge Port"

    # 13. GEM IWTP 266_2 -> GEM Port 268_2
    # Verify that the second Interworking TP correctly links to the second GEM CTP
    e13 = find_edge("266_2", "268_2")
    assert e13 is not None, "Edge from GEM IWTP (266_2) to GEM Port (268_2) is missing"
    assert e13["relation"] == "iw_linked_to_gem_port", (
        f"Relation mismatch for edge 266_2->268_2: {e13.get('relation')}"
    )
    assert e13["label"] == "gem_ptr", "Human label 'gem_ptr' missing for secondary IWTP"

    # 14. GEM IWTP 266_2 -> Dot1p Mapper 130_2 (Service Profile Mapping)
    # Verify that the second IWTP points to its assigned 802.1p Mapper instance
    e14 = find_edge("266_2", "130_2")
    assert e14 is not None, (
        "Edge from GEM IWTP (266_2) to Service Profile (130_2) is missing"
    )
    assert e14["relation"] == "service_profile_mapping", (
        "AI relation for 266_2->130_2 should be service_profile_mapping"
    )
    assert e14["label"] == "srv_ptr", (
        "Label 'srv_ptr' missing for service profile mapping"
    )

    # 15. VLAN Filter 84_3 -> Bridge Port 47_3 (Implicit Match)
    # Final check for the implicit ID-based binding between VLAN filter and its bridge port
    e15 = find_edge("84_3", "47_3")
    assert e15 is not None, (
        "Implicit edge from VLAN Filter (84_3) to Port (47_3) is missing"
    )
    assert e15["relation"] == "vlan_filter_bind_to_port", (
        "AI relation mismatch for implicit filter binding on port 3"
    )
    assert e15["label"] == "Filter-on", (
        "Human label 'Filter-on' missing for ME 84 instance 3"
    )
