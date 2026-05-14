#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
from scapy.all import rdpcap
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.box import SIMPLE, ROUNDED
from omci.omci import OMCIBaseline, OMCIPacket, OmciResult, OmciAction
from omci import omcimib
from omci import omcigrapher
from omci.omcivlan import VlanTaggingOperation
from omci.omcimib import ME_171_ASSOCIATION_TYPE
from omci.omciflow import show_tcont_speed_flow
import argparse
import json


def is_baseline(pkt):
    return isinstance(pkt, OMCIBaseline)


def run_omcicheck(
    pcap_path,
    only_vendor=False,
    only_failed=False,
    rtt_threshold=1000,
    json_output=False,
):
    try:
        raw_pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    count_fail = 0
    count_vendor = 0
    count_duplicate = 0
    count_late = 0
    request_timestamps = {}
    check_result = {
        "packets": [],
        "summary": {
            "resp_fail_count": 0,
            "is_vendor_me_count": 0,
            "transaction_id_duplicate_count": 0,
            "resp_late_count": 0,
        },
    }

    for i, raw_pkt in enumerate(raw_pkts):
        # Skip non-OMCI packets
        if not raw_pkt.haslayer("Ether") or raw_pkt.getlayer("Ether").type != 0x88B5:
            continue
        raw_data = bytes(raw_pkt.lastlayer())
        try:
            omci_pkt = OMCIPacket.from_raw(raw_data)
        except Exception:
            continue

        # currently, only support Baseline
        if not is_baseline(omci_pkt):
            continue

        is_fail = False
        is_vendor = False
        is_duplicate = False
        is_late = False
        action_name = ""
        resp_result = {}
        rtt = 0
        status = ""

        # rtt
        if omci_pkt.is_request:
            if omci_pkt.transaction_id in request_timestamps:
                status = "[TID_DUPLOCATE]"
                count_duplicate += 1
                is_duplicate = True
            request_timestamps[omci_pkt.transaction_id] = raw_pkt.time

        # Display Non-standard MEs reported by ONU during MIB Upload.
        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
        else:
            me_class = omci_pkt.me_class
            me_inst = omci_pkt.inst_id

        # Display non-standard MEs and non-success responses during OLT provisioning.
        if omci_pkt.result is not None:
            res_val = omci_pkt.result
            resp_result["code"] = res_val
            if resp_result["code"] != OmciResult.SUCCESS:
                is_fail = True
                count_fail += 1
                resp_result["success"] = False
                try:
                    resp_result["text"] = f"Err: {OmciResult(res_val).name}"
                except ValueError:
                    resp_result["text"] = "Err: Unknown"
            else:
                resp_result["success"] = True
                resp_result["text"] = "SUCCESS"

            if omci_pkt.transaction_id in request_timestamps:
                rtt = raw_pkt.time - request_timestamps[omci_pkt.transaction_id]
                if rtt * 1000 > rtt_threshold:
                    is_late = True
                    count_late += 1
                    status = "[LATE]"

        if (
            omci_pkt.is_vendor_me
            or omci_pkt.is_feature_me
            or omci_pkt.mib_upload_is_vendor
            or omci_pkt.mib_upload_is_feature
        ):
            is_vendor = True
            count_vendor += 1

        if only_vendor and not is_vendor:
            continue
        if only_failed and not is_fail:
            continue

        me_desc = omcimib.get_me_name(me_class)
        if is_fail or is_vendor or is_duplicate or is_late:
            action_name = (
                omci_pkt.action.name
                if hasattr(omci_pkt.action, "name")
                else f"Action({omci_pkt.action})"
            )
            check_result["packets"].append(
                {
                    "packet_no": i + 1,
                    "transaction_id": omci_pkt.transaction_id,
                    "action": action_name,
                    "me_class": me_class,
                    "me_instance_id": me_inst,
                    "me_name": me_desc,
                    "result": resp_result,
                    "rtt": float(rtt),
                    "status": status,
                    "from_olt": omci_pkt.is_request,
                }
            )
    check_result["summary"] = {
        "resp_fail_count": count_fail,
        "is_vendor_me_count": count_vendor,
        "resp_late_count": count_late,
        "transaction_id_duplicate_count": count_duplicate,
    }

    if json_output:
        print(json.dumps(check_result, indent=2))
    else:
        from .omcirich import render_check_table

        render_check_table(check_result)


def load_mib_json(json_path):
    """
    Dynamic loading of external JSON configurations, allowing users to overwritestandard ME definitions
    or define custom Vendor-specific ME specifications.
    """
    if not json_path or not os.path.exists(json_path):
        return
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            custom_me = json.load(f)
            for cid, spec in custom_me.items():
                omcimib.ME_SPEC[int(cid)] = tuple(spec)
            print(f"[*] Successfully loaded {len(custom_me)} custom ME specs.")
    except Exception as e:
        print(f"[!] Error loading MIB JSON: {e}")


def get_mib_snapshot(pcap_path):
    snapshot = {}  # {(class_id, inst_id): MIBInstance}

    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return snapshot

    for i, pkt in enumerate(pkts):
        # Skip non-OMCI packets
        if not pkt.haslayer("Ether") or pkt.getlayer("Ether").type != 0x88B5:
            continue
        raw_data = bytes(pkt.lastlayer())
        try:
            omci_pkt = OMCIPacket.from_raw(raw_data)
        except Exception:
            continue

        # currently, only support Baseline
        if not is_baseline(omci_pkt):
            continue

        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
            attr_mask = mib_entity["attr_mask"]
            attr_data = mib_entity["attr_data"]
            key = (me_class, me_inst)
            if key not in snapshot:
                snapshot[key] = omcimib.MIBInstance(me_class, me_inst)
            snapshot[key].update(attr_mask, attr_data)

    return snapshot


def run_omcidiff(pcap1, pcap2):
    print(f"[*] Analyzing MIB from {pcap1}...")
    mib1 = get_mib_snapshot(pcap1)

    print(f"[*] Analyzing MIB from {pcap2}...")
    mib2 = get_mib_snapshot(pcap2)

    all_keys = sorted(set(mib1.keys()) | set(mib2.keys()))
    print(
        f"\n{'ME (Class, Inst)':<35} | {'Attribute':<35} | {'Pcap 1':<20} -> {'Pcap 2'}"
    )
    print("-" * 120)

    for key in all_keys:
        if key not in mib2:
            me_name = omcimib.get_me_name(key[0])
            print(f"\033[91m[REMOVED] {me_name} {key}\033[0m")
            continue

        if key not in mib1:
            me_name = omcimib.get_me_name(key[0])
            print(f"\033[92m[NEW]     {me_name} {key}\033[0m")
            continue

        obj1 = mib1[key]
        obj2 = mib2[key]
        me_name = omcimib.get_me_name(key[0])

        if obj1.is_unknown:
            obj1.vendor_data.sort(key=lambda x: x[0], reverse=True)
            obj2.vendor_data.sort(key=lambda x: x[0], reverse=True)

            masks1 = [m for m, d in obj1.vendor_data]
            masks2 = [m for m, d in obj2.vendor_data]
            if masks1 != masks2:
                print(
                    f"[!] {me_name:<20} {str(key):<14} | Mask Mismatch: {masks1} vs {masks2}"
                )
            else:
                for i, (mask, d1) in enumerate(obj1.vendor_data):
                    d2 = obj2.vendor_data[i][1]
                    if d1 != d2:
                        attr_label = f"Vendor Raw (Mask 0x{mask:04X})"
                        print(
                            f"[*] {me_name:<20} {str(key):<14} | {attr_label:<35} | {d1:<20} -> {d2}"
                        )
        else:
            for attr, val1 in obj1.attributes.items():
                val2 = obj2.attributes.get(attr)
                if val1 != val2:
                    v1_str = f"0x{val1:x}" if isinstance(val1, int) else f"'{val1}'"
                    v2_str = f"0x{val2:x}" if isinstance(val2, int) else f"'{val2}'"
                    print(
                        f"[*] {me_name:<20} {str(key):<14} | {attr:<35} | {v1_str:<20} -> {v2_str}"
                    )

    print("-" * 120)


def get_all_mib_db(pcap_path):
    mib_db = {}  # {(class_id, inst_id): MIBInstance}

    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return mib_db

    for i, pkt in enumerate(pkts):
        # Skip non-OMCI packets
        if not pkt.haslayer("Ether") or pkt.getlayer("Ether").type != 0x88B5:
            continue
        raw_data = bytes(pkt.lastlayer())
        try:
            omci_pkt = OMCIPacket.from_raw(raw_data)
        except Exception:
            continue

        # currently, only support Baseline
        if not is_baseline(omci_pkt):
            continue

        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
            attr_mask = mib_entity["attr_mask"]
            attr_data = mib_entity["attr_data"]
            key = (me_class, me_inst)

            if key not in mib_db:
                mib_db[key] = omcimib.MIBInstance(me_class, me_inst)
            mib_db[key].update(attr_mask, attr_data)
            continue

        if not omci_pkt.is_request:
            continue

        me_class = omci_pkt.me_class
        me_inst = omci_pkt.inst_id
        key = (me_class, me_inst)
        if omci_pkt.action == OmciAction.CREATE:
            if key not in mib_db:
                mib_db[key] = omcimib.MIBInstance(me_class, me_inst)
            mib_db[key].update_from_create(omci_pkt.content)
        elif omci_pkt.action == OmciAction.SET:
            if key in mib_db:
                attr_mask = int.from_bytes(omci_pkt.content[:2], byteorder="big")
                attr_data = omci_pkt.content[2:]
                mib_db[key].update(attr_mask, attr_data)

    return mib_db


def get_instances_by_class(mib_db, target_class_id):
    matched = [inst for k, inst in mib_db.items() if k[0] == target_class_id]
    matched.sort(key=lambda x: x.inst_id)

    return matched


def run_omcigraph(pcap):
    print(f"[*] Analyzing MIB from {pcap}...")
    mib_db = get_all_mib_db(pcap)
    html_content = omcigrapher.export_to_html(mib_db)
    with open("output.html", "w", encoding="utf-8") as f:
        f.write(html_content)


def get_downstream_semantic(mode):
    mapping = {
        0: "Inverse (ONU Std)",
        1: "Transparent (No Change)",
        2: "Match VID+P -> Inverse (Else: Fwd)",
        3: "Match VID -> Inverse (Else: Fwd)",
        4: "Match Pbit -> Inverse (Else: Fwd)",
        5: "Match VID+P -> Inverse (Else: Drop)",
        6: "Match VID -> Inverse (Else: Drop)",
        7: "Match Pbit -> Inverse (Else: Drop)",
        8: "Block All",
    }
    return mapping.get(mode, f"M{mode}?")


def run_omcivlan(pcap):
    console = Console()

    mib_db = get_all_mib_db(pcap)
    vlan_db = get_instances_by_class(mib_db, 171)

    # Main Table
    main_table = Table(
        title="[bold white]OMCI VLAN Logic Analyzer[/]",
        box=ROUNDED,
        header_style="bold magenta",
        show_lines=True,
        expand=True,
    )

    main_table.add_column("ME inst ID", justify="center", style="cyan", width=12)
    main_table.add_column("VLAN Rules (Sub-Table)", width=75)
    main_table.add_column("Association / Mode", justify="center", width=20)

    for vlan in vlan_db:
        inst_id = vlan.inst_id
        attrs = vlan.attributes

        # --- Sub-Table for VLAN rules ---
        sub_table = Table(box=SIMPLE, header_style="italic yellow", expand=True)
        sub_table.add_column("Idx", width=4, justify="center")
        sub_table.add_column("Action / Semantic", width=25)
        sub_table.add_column("Detailed Bit-Fields (Filter / Treatment / Tags Removed )")

        raw_rows = attrs.get("Received frame VLAN tagging operation table", [])
        rows = raw_rows if isinstance(raw_rows, list) else [raw_rows]

        for idx, row_hex in enumerate(rows):
            vlan_op = VlanTaggingOperation(row_hex)
            d = vlan_op.data

            idx_style = "bold red"
            idx_text = Text(str(idx), style=idx_style)

            # Bit-Fields
            # F: Filter, T: Treatment, R: Remove Tag
            bit_info = (
                f"[dim]F:[/] [cyan]O:{d['f_out_prio']}/{d['f_out_vid']} I:{d['f_in_prio']}/{d['f_in_vid']} E:{d['f_eth_type']}[/] "
                f"[dim]T:[/] [yellow]O:{d['t_out_prio']}/{d['t_out_vid']} I:{d['t_in_prio']}/{d['t_in_vid']}[/] "
                f"[magenta]R:{d['t_tags_rem']}[/]"
            )

            sub_table.add_row(
                idx_text,
                Text(vlan_op.action_type, style="bold green"),
                bit_info,
            )

        # --- Association / Mode ---
        assoc_ptr = attrs.get("Associated ME pointer", "N/A")
        assoc_type = attrs.get("Association type", -1)
        assoc_type_desc = ME_171_ASSOCIATION_TYPE.get(assoc_type, "Unknown")
        ds_mode = vlan.attributes.get("Downstream mode", 0)
        ds_mode_desc = get_downstream_semantic(ds_mode)

        # --- Path Info ---
        main_table.add_row(
            str(inst_id),
            sub_table,
            f"{assoc_type_desc}\n{assoc_ptr}\n[dim]Mode: {ds_mode_desc}[/]",
        )

    console.print(main_table)


def run_tcont_flow(pcap):
    mib_db = get_all_mib_db(pcap)
    show_tcont_speed_flow(mib_db)


def main():
    parser = argparse.ArgumentParser(
        prog="omcipcap", description="OMCI PCAP Diagnostic & Analysis Tool"
    )

    common_args = argparse.ArgumentParser(add_help=False)
    common_args.add_argument(
        "--json-output", action="store_true", help="Output results in JSON format"
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available analysis commands"
    )

    # --- Sub-command: check ---
    check_p = subparsers.add_parser(
        "check", parents=[common_args], help="Analyze RTT, TID duplicates, and failures"
    )
    check_p.add_argument("pcap", help="Path to pcap file")
    check_p.add_argument(
        "--rtt-threshold", type=float, default=1000.0, help="RTT threshold in ms"
    )
    check_p.add_argument("--only-vendor", action="store_true")
    check_p.add_argument("--only-failed", action="store_true")

    # --- Sub-command: diff ---
    diff_p = subparsers.add_parser(
        "diff", help="Compare MIB snapshots between two pcaps"
    )
    diff_p.add_argument("pcap1", help="Baseline pcap")
    diff_p.add_argument("pcap2", help="Target pcap")
    diff_p.add_argument("--mib-json", help="Custom ME JSON definition")

    # --- Sub-command: graphic ---
    graph_p = subparsers.add_parser(
        "graphic", help="Generate interactive topology HTML"
    )
    graph_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: vlan_tbl ---
    vlan_p = subparsers.add_parser(
        "vlan_tbl", help="Analye OMCI VLAN tagging logic (Table-driven)"
    )
    vlan_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: tcont_flow ---
    vlan_p = subparsers.add_parser(
        "tcont_flow", help="Trace T-CONT -> GEM -> PQ traffic hierarchy"
    )
    vlan_p.add_argument("pcap", help="Path to pcap file")

    args = parser.parse_args()

    if args.command == "check":
        run_omcicheck(
            args.pcap,
            args.only_vendor,
            args.only_failed,
            args.rtt_threshold,
            json_output=args.json_output,
        )
    elif args.command == "diff":
        if args.mib_json:
            load_mib_json(args.mib_json)
        run_omcidiff(args.pcap1, args.pcap2)
    elif args.command == "graphic":
        run_omcigraph(args.pcap)
    elif args.command == "vlan_tbl":
        run_omcivlan(args.pcap)
    elif args.command == "tcont_flow":
        run_tcont_flow(args.pcap)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
