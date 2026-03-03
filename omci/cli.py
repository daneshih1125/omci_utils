#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import sys
import os
from scapy.all import rdpcap
from omci.omci import OMCIBaseline, OMCIPacket, OmciResult, OmciAction
from  omci import omcimib
import argparse
import json

def is_baseline(pkt):
    return isinstance(pkt, OMCIBaseline)

def run_omcicheck(pcap_path, only_vendor=False, only_failed=False, rtt_threshold=1000):
    print(f"Analyzing: {pcap_path}\n")
    header = f"{'No.':<6} {'ID':<8} {'Action':<18} {'ME Class':<12} {'ME Instance':<12} {'Result':<30} {'RTT':<12} {'Status':<16} {'ME desc':<40}"
    print(header)
    print("-" * 120)

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

    for i, raw_pkt in enumerate(raw_pkts):
        # Skip non-OMCI packets
        if not raw_pkt.haslayer('Ether') or raw_pkt.getlayer('Ether').type != 0x88b5:
            continue
        raw_data = bytes(raw_pkt.lastlayer())
        try:
            pkt = OMCIPacket.from_raw(raw_data)
        except Exception:
            continue

        # currently, only support Baseline
        if not is_baseline(pkt):
            continue

        is_fail = False
        is_vendor = False
        is_duplicate = False
        is_late = False
        action_name = ""
        me_display = ""
        inst_display = ""
        res_text = ""
        rtt = 0
        status = ""

        # rtt
        if pkt.is_request:
            if pkt.transaction_id in request_timestamps:
                status = "[TID_DUPLOCATE]"
                count_duplicate += 1
                is_duplicate = True
            request_timestamps[pkt.transaction_id] = raw_pkt.time

        # Display Non-standard MEs reported by ONU during MIB Upload.
        mib_entity = pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
        else:
            me_class = pkt.me_class
            me_inst = pkt.inst_id

        # Display non-standard MEs and non-success responses during OLT provisioning.
        if pkt.result != None:
            res_val = pkt.result
            if res_val != OmciResult.SUCCESS:
                is_fail = True
                count_fail += 1
                try:
                    res_text = f"Err: {OmciResult(res_val).name} ({res_val})"
                except ValueError:
                    res_text = f"Err: Unknown ({res_val})"
            else:
                res_text = "Success"

            if pkt.transaction_id in request_timestamps:
                rtt = raw_pkt.time - request_timestamps[pkt.transaction_id]
                if rtt * 1000 > rtt_threshold:
                    is_late = True
                    count_late += 1
                    status = "[LATE]"


        if pkt.is_vendor_me or pkt.is_feature_me or pkt.mib_upload_is_vendor or pkt.mib_upload_is_feature:
            is_vendor = True
            count_vendor += 1

        if only_vendor and not is_vendor:
            continue
        if only_failed and not is_fail:
            continue

        me_desc = omcimib.get_me_name(me_class)

        if is_fail or is_vendor or is_duplicate or is_late:
            color = "\033[91m" if is_fail else "\033[93m"
            reset = "\033[0m"
            action_name = pkt.action.name if hasattr(pkt.action, 'name') else f"Action({pkt.action})"
            inst_str = f"0x{me_inst:04x}"
            print(f"{color}{i+1:<6} {pkt.transaction_id:<8} {action_name:<18} {me_class:<12} {inst_str:<12} {res_text:<30} {rtt:<12} {status:<16} {me_desc:<40}{reset}")

    print("-" * 120)

    print(f"Summary: Found {count_fail} failures, {count_vendor} Vendor packets, {count_duplicate} duplicate packets, {count_late} late packets")

def load_mib_json(json_path):
    """
    Dynamic loading of external JSON configurations, allowing users to overwritestandard ME definitions
    or define custom Vendor-specific ME specifications.
    """
    if not json_path or not os.path.exists(json_path):
        return
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
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
        if not pkt.haslayer('Ether') or pkt.getlayer('Ether').type != 0x88b5:
            continue
        raw_data = bytes(pkt.lastlayer())
        try:
            pkt = OMCIPacket.from_raw(raw_data)
        except Exception:
            continue

        # currently, only support Baseline
        if not is_baseline(pkt):
            continue

        mib_entity = pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
            attr_mask = mib_entity["attr_mask"]
            attr_data = mib_entity["attr_data"]
            key = (me_class, me_inst)

            snapshot[key] = omcimib.MIBInstance(me_class, me_inst)
            snapshot[key].update(attr_mask, attr_data)


    return snapshot

def run_omcidiff(pcap1, pcap2):
    print(f"[*] Analyzing MIB from {pcap1}...")
    mib1 = get_mib_snapshot(pcap1)

    print(f"[*] Analyzing MIB from {pcap2}...")
    mib2 = get_mib_snapshot(pcap2)

    all_keys = sorted(set(mib1.keys()) | set(mib2.keys()))
    print(f"\n{'ME (Class, Inst)':<35} | {'Attribute':<35} | {'Pcap 1':<20} -> {'Pcap 2'}")
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
                print(f"[!] {me_name:<20} {str(key):<14} | Mask Mismatch: {masks1} vs {masks2}")
            else:
                for i, (mask, d1) in enumerate(obj1.vendor_data):
                    d2 = obj2.vendor_data[i][1]
                    if d1 != d2:
                        attr_label = f"Vendor Raw (Mask 0x{mask:04X})"
                        print(f"[*] {me_name:<20} {str(key):<14} | {attr_label:<35} | {d1:<20} -> {d2}")
        else:
            for attr, val1 in obj1.attributes.items():
                val2 = obj2.attributes.get(attr)
                if val1 != val2:
                    v1_str = f"0x{val1:x}" if isinstance(val1, int) else f"'{val1}'"
                    v2_str = f"0x{val2:x}" if isinstance(val2, int) else f"'{val2}'"
                    print(f"[*] {me_name:<20} {str(key):<14} | {attr:<35} | {v1_str:<20} -> {v2_str}")

    print("-" * 120)


def main():
    prog_name = os.path.basename(sys.argv[0])

    if prog_name == "omcicheck":
        parser = argparse.ArgumentParser(description="OMCI Check Tool")
        parser.add_argument("pcap", help="Path to pcap file")
        parser.add_argument("--only-vendor", action="store_true")
        parser.add_argument("--only-failed", action="store_true")
        parser.add_argument(
            "--rtt-threshold",
            type=float,
            default=1000.0,
            help="RTT threshold in milliseconds to flag slow responses (default: 1000ms)"
        )

        args = parser.parse_args()
        run_omcicheck(args.pcap, only_vendor=args.only_vendor, only_failed=args.only_failed, rtt_threshold=args.rtt_threshold)
    elif prog_name == "omcidiff":
        parser = argparse.ArgumentParser(description="OMCI MIB Diff Tool")
        parser.add_argument("pcap1", help="Path to the first pcap file (Baseline)")
        parser.add_argument("pcap2", help="Path to the second pcap file (Target)")
        parser.add_argument("--mib-json", help="Path to custom ME JSON definition file", default=None)

        args = parser.parse_args()

        if args.mib_json:
            load_mib_json(args.mib_json)
        run_omcidiff(args.pcap1, args.pcap2)

if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:
