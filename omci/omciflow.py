#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from omci.omcimib import OMCIClass


def get_bw_info(mib_db, descriptor_ptr):
    """Get BW (Mbps) from Traffic Descriptor (280)"""

    if (
        not descriptor_ptr
        or (OMCIClass.TRAFFIC_DESCRIPTOR, descriptor_ptr) not in mib_db
    ):
        return "Unrestricted"

    td = mib_db[(OMCIClass.TRAFFIC_DESCRIPTOR, descriptor_ptr)]

    cir_bytes = td.attributes.get("CIR", 0)
    pir_bytes = td.attributes.get("PIR", 0)

    if cir_bytes == 0 and pir_bytes == 0:
        return "Factory Policy"

    cir_mbps = (cir_bytes * 8) / 1_000_000
    pir_mbps = (pir_bytes * 8) / 1_000_000

    return f"CIR={cir_mbps:g}Mbps/PIR={pir_mbps:g}Mbps"


def get_tcont_flow_data(mib_db):
    """
    Analyzes the GPON T-CONT -> GEM -> PQ hierarchy and returns a structured list.

    Returns:
        list: A list of T-CONT dictionaries containing GEM port details and flow info.
    """
    if not mib_db:
        return []

    # Filter and sort T-CONTs (ME Class 262)
    tcont_instances = [inst for k, inst in mib_db.items() if k[0] == OMCIClass.T_CONT]
    tcont_instances.sort(key=lambda x: x.inst_id)

    tcont_flow_list = []

    for tcont in tcont_instances:
        alloc_id = tcont.attributes.get("Alloc-ID", 0xFFFF)

        tcont_entry = {
            "tcont_id": tcont.inst_id,
            "alloc_id": None if alloc_id == 0xFFFF or alloc_id == 0xFF else alloc_id,
            "gem_ports": [],
        }

        # Find GEM Port Network CTPs (ME Class 268) pointing to this T-CONT
        gems = [
            inst
            for k, inst in mib_db.items()
            if k[0] == OMCIClass.GEM_PORT_NETWORK_CTP
            and inst.attributes.get("T-CONT pointer") == tcont.inst_id
        ]

        for gem in gems:
            # --- Upstream Path ---
            up_pq_ptr = gem.attributes.get("Traffic management pointer upstream", 0)
            up_bw = get_bw_info(
                mib_db,
                gem.attributes.get(
                    "Traffic descriptor profile pointer for upstream", 0
                ),
            )

            # --- Downstream Path ---
            ds_pq_ptr = gem.attributes.get("Priority queue pointer for downstream", 0)
            dn_bw = get_bw_info(
                mib_db,
                gem.attributes.get(
                    "Traffic descriptor profile pointer for downstream", 0
                ),
            )

            # --- Decode Downstream Priority ---
            ds_pq = mib_db.get((OMCIClass.PRIORITY_QUEUE_G, ds_pq_ptr))
            ds_prio_val = None
            if ds_pq:
                related_port = ds_pq.attributes.get("Related port", "")
                try:
                    if isinstance(related_port, str) and len(related_port) >= 8:
                        # Extract priority from the Related Port bitmask
                        ds_prio_val = int(related_port[6:], 16) & 0x7
                except (ValueError, IndexError):
                    pass

            gem_entry = {
                "gem_port_id": gem.attributes.get("Port-ID", "N/A"),
                "upstream": {"pq_ptr": up_pq_ptr, "bandwidth": up_bw},
                "downstream": {
                    "pq_ptr": ds_pq_ptr,
                    "priority": ds_prio_val,
                    "bandwidth": dn_bw,
                },
            }
            tcont_entry["gem_ports"].append(gem_entry)

        tcont_flow_list.append(tcont_entry)

    return tcont_flow_list
