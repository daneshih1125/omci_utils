#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
from omci import omcimib
from omci import omcigrapher
from omci import omciparser
import argparse
import json


def run_omcicheck(
    pcap_path,
    only_vendor=False,
    only_failed=False,
    rtt_threshold=1000,
    json_output=False,
):

    check_result = omciparser.get_check_results(
        pcap_path, only_vendor, only_failed, rtt_threshold
    )

    if json_output:
        print(json.dumps(check_result, indent=2))
    else:
        from .omcirich import render_check_table

        render_check_table(check_result)


def run_omcidiff(pcap1, pcap2):
    print(f"[*] Analyzing MIB from {pcap1}...")
    mib1 = omciparser.get_mib_snapshot(pcap1)

    print(f"[*] Analyzing MIB from {pcap2}...")
    mib2 = omciparser.get_mib_snapshot(pcap2)

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


def run_omcigraph(pcap):
    print(f"[*] Analyzing MIB from {pcap}...")
    mib_db = omciparser.get_all_mib_db(pcap)
    html_content = omcigrapher.export_to_html(mib_db)
    with open("output.html", "w", encoding="utf-8") as f:
        f.write(html_content)


def run_omcivlan(pcap, json_output=False):
    mib_db = omciparser.get_all_mib_db(pcap)
    vlan_data = omciparser.get_vlan_data(mib_db)

    if json_output:
        print(json.dumps(vlan_data, indent=2))
    else:
        from .omcirich import render_vlan_table

        render_vlan_table(vlan_data)


def run_tcont_flow(pcap, json_output=False):
    mib_db = omciparser.get_all_mib_db(pcap)
    flow_data = omciparser.get_flow_data(mib_db)

    if json_output:
        print(json.dumps(flow_data, indent=2))
    else:
        from .omcirich import render_tcont_flow_tree

        render_tcont_flow_tree(flow_data)


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


def main():
    parser = argparse.ArgumentParser(
        prog="omcipcap", description="OMCI PCAP Diagnostic & Analysis Tool"
    )

    common_args = argparse.ArgumentParser(add_help=False)
    common_args.add_argument(
        "-j", "--json-output", action="store_true", help="Output results in JSON format"
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
        "vlan_tbl",
        parents=[common_args],
        help="Analye OMCI VLAN tagging logic (Table-driven)",
    )
    vlan_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: tcont_flow ---
    tcont_p = subparsers.add_parser(
        "tcont_flow",
        parents=[common_args],
        help="Trace T-CONT -> GEM -> PQ traffic hierarchy",
    )
    tcont_p.add_argument("pcap", help="Path to pcap file")

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
        run_omcivlan(args.pcap, json_output=args.json_output)
    elif args.command == "tcont_flow":
        run_tcont_flow(args.pcap, json_output=args.json_output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
