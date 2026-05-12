#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from rich.console import Console
from rich.tree import Tree
from omci.omcimib import OMCIClass

def get_bw_info(mib_db, descriptor_ptr):
    """ Get BW (Mbps) from Traffic Descriptor (280) """

    if not descriptor_ptr or (OMCIClass.TRAFFIC_DESCRIPTOR, descriptor_ptr) not in mib_db:
        return "Unrestricted"

    td = mib_db[(OMCIClass.TRAFFIC_DESCRIPTOR, descriptor_ptr)]

    cir_bytes = td.attributes.get('CIR', 0)
    pir_bytes = td.attributes.get('PIR', 0)

    if cir_bytes == 0 and pir_bytes == 0:
        return "Factory Policy"

    cir_mbps = (cir_bytes * 8) / 1_000_000
    pir_mbps = (pir_bytes * 8) / 1_000_000

    return f"CIR={cir_mbps:g}Mbps/PIR={pir_mbps:g}Mbps"

def show_tcont_speed_flow(mib_db):
    console = Console()
    if not mib_db:
        console.print("[red]MIB Database is empty.[/red]")
        return

    # T-CONTS
    tconts = [inst for k, inst in mib_db.items() if k[0] == OMCIClass.T_CONT]
    tconts.sort(key=lambda x: x.inst_id)

    flow_tree = Tree("[bold cyan]GPON T-CONT Flow Analysis[/bold cyan]")

    for tcont in tconts:
        alloc_id = tcont.attributes.get('Alloc-ID', 0xFFFF)
        # Unassigned Alloc-ID
        alloc_str = f"alloc-id={alloc_id}" if alloc_id != 0xFFFF else "[dim]Unassigned[/dim]"
        t_node = flow_tree.add(f"[bold magenta]T-CONT {tcont.inst_id}[/bold magenta] ({alloc_str})")

        # Find gems pointer to T-CONT
        gems = [inst for k, inst in mib_db.items()
                if k[0] == OMCIClass.GEM_PORT_NETWORK_CTP and
                inst.attributes.get('T-CONT pointer') == tcont.inst_id]

        for gem in gems:
            gem_id = gem.attributes.get('Port-ID', 'N/A')
            # --- Upstream Path ---
            up_pq_ptr = gem.attributes.get('Traffic management pointer upstream', 0)
            up_bw = get_bw_info(mib_db, gem.attributes.get('Traffic descriptor profile pointer for upstream', 0))

            # --- Downstream Path ---
            ds_pq_ptr = gem.attributes.get('Priority queue pointer for downstream', 0)
            dn_bw = get_bw_info(mib_db, gem.attributes.get('Traffic descriptor profile pointer for downstream', 0))

            ds_pq = mib_db.get((OMCIClass.PRIORITY_QUEUE_G, ds_pq_ptr))
            if ds_pq is None:
                ds_prio = f"PQ {ds_pq_ptr} not found"
            else:
                related_port = ds_pq.attributes.get("Related port", "")
                try:
                    if isinstance(related_port, str) and len(related_port) >= 8:
                        ds_prio = f"Priority {int(related_port[6:], 16) & 0x7}"
                    else:
                        ds_prio = "Priority Unknown"
                except (ValueError, IndexError):
                    ds_prio = "Priority Error"

            gem_node = t_node.add(f"[bold yellow]GEM {gem_id}[/bold yellow]")
            gem_node.add(f"[bold cyan][US][/bold cyan] PQ {up_pq_ptr} → up:{up_bw}")
            gem_node.add(f"[bold green][DS][/bold green] PQ {ds_pq_ptr} → Priority {ds_prio} dn:{dn_bw}")

    console.print(flow_tree)
