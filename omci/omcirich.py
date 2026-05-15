#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.tree import Tree


def render_check_table(check_result):
    """
    Renders the OMCI packet consistency check results in a formatted table.
    """

    pkts = check_result.get("packets", [])
    summary = check_result.get("summary", {})

    if len(pkts) == 0:
        print("No Vendor and failed packtes detected")
        return

    console = Console()
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.HORIZONTALS,
        padding=(0, 2),
        min_width=120,
        collapse_padding=True,
    )

    table.add_column("No.", style="cyan")
    table.add_column("ID", style="magenta")
    table.add_column("Action")
    table.add_column("ME Class")
    table.add_column("ME Instance")
    table.add_column("Result")
    table.add_column("RTT", justify="right")
    table.add_column("Status", style="red")
    table.add_column("ME desc", style="green")

    for pkt in check_result["packets"]:
        rtt_val = pkt.get("rtt")
        if rtt_val == 0.0:
            rtt_display = "0"
        else:
            rtt_display = f"{float(rtt_val):.6f}" if rtt_val is not None else "-"

        res = pkt.get("result", {})
        res_text = res.get("text", "")
        row_style = ""
        if "Err" in res_text or pkt.get("status"):
            row_style = "bold red"
        elif pkt.get("from_olt"):
            row_style = "cyan"
        table.add_row(
            str(pkt["packet_no"]),
            str(pkt["transaction_id"]),
            pkt["action"],
            str(pkt["me_class"]),
            f"0x{pkt['me_instance_id']:04x}",
            res_text,
            rtt_display,
            str(pkt["status"]),
            pkt["me_name"],
            style=row_style,
        )

    console.print(table)
    console.print(
        f"[bold]Summary:[/bold] Found [red]{summary['resp_fail_count']}[/red] failures, "
        f"{summary['is_vendor_me_count']} Vendor packets, "
        f"{summary['transaction_id_duplicate_count']} duplicate packets, "
        f"{summary['resp_late_count']} late packets\n"
    )


def render_vlan_table(vlan_data_list):
    """
    Renders the OMCI VLAN Logic Analysis table (ME 171).
    - Decodes nested VLAN tagging operation rules.
    - Displays association pointers and downstream modes.
    """

    console = Console()
    if not vlan_data_list:
        console.print("[yellow]No VLAN (ME 171) instances found.[/]")
        return

    main_table = Table(
        title="[bold white]OMCI VLAN Logic Analyzer[/]",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
        expand=True,
    )

    main_table.add_column("ME inst ID", justify="center", style="cyan", width=12)
    main_table.add_column("VLAN Rules (Sub-Table)", width=75)
    main_table.add_column("Association / Mode", justify="center", width=20)

    for vlan in vlan_data_list:
        # --- Sub-Table for VLAN rules ---
        sub_table = Table(box=box.SIMPLE, header_style="italic yellow", expand=True)
        sub_table.add_column("Idx", width=4, justify="center")
        sub_table.add_column("Action / Semantic", width=25)
        sub_table.add_column("Detailed Bit-Fields (Filter / Treatment / Tags Removed )")

        for idx, rule in enumerate(vlan["rules"]):
            d = rule["data"]
            bit_info = (
                f"[dim]F:[/] [cyan]O:{d['f_out_prio']}/{d['f_out_vid']} I:{d['f_in_prio']}/{d['f_in_vid']} E:{d['f_eth_type']}[/] "
                f"[dim]T:[/] [yellow]O:{d['t_out_prio']}/{d['t_out_vid']} I:{d['t_in_prio']}/{d['t_in_vid']}[/] "
                f"[magenta]R:{d['t_tags_rem']}[/]"
            )

            sub_table.add_row(
                Text(str(idx), style="bold red"),
                Text(rule["action_type"], style="bold green"),
                bit_info,
            )

        main_table.add_row(
            str(vlan["inst_id"]),
            sub_table,
            f"{vlan['assoc_type']}\n{vlan['assoc_ptr']}\n[dim]Mode: {vlan['ds_mode']}[/]",
        )

    console.print(main_table)


def render_tcont_flow_tree(flow_data):
    """
    Renders the GPON T-CONT -> GEM -> PQ hierarchy using a Rich Tree.
    This replaces the old direct-to-console logic.
    """
    console = Console()
    if not flow_data:
        console.print("[red]No T-CONT flow data found to render.[/red]")
        return

    # Create the root of the tree
    flow_tree = Tree("[bold cyan]GPON T-CONT Flow Analysis[/bold cyan]")

    for tcont in flow_data:
        # Handle unassigned Alloc-ID (which we set to None in get_tcont_flow_data)
        alloc_id = tcont.get("alloc_id")
        alloc_str = (
            f"alloc-id={alloc_id}" if alloc_id is not None else "[dim]Unassigned[/dim]"
        )

        # Add T-CONT node
        t_node = flow_tree.add(
            f"[bold magenta]T-CONT {tcont['tcont_id']}[/bold magenta] ({alloc_str})"
        )

        for gem in tcont.get("gem_ports", []):
            # Add GEM node
            gem_id = gem.get("gem_port_id", "N/A")
            gem_node = t_node.add(f"[bold yellow]GEM {gem_id}[/bold yellow]")

            # Add Upstream (US) details
            us = gem.get("upstream", {})
            gem_node.add(
                f"[bold cyan][US][/bold cyan] PQ {us.get('pq_ptr')} → up:{us.get('bandwidth')}"
            )

            # Add Downstream (DS) details
            ds = gem.get("downstream", {})
            prio = ds.get("priority")
            prio_str = f"Priority {prio}" if prio is not None else "Priority Unknown"
            gem_node.add(
                f"[bold green][DS][/bold green] PQ {ds.get('pq_ptr')} → {prio_str} dn:{ds.get('bandwidth')}"
            )

    console.print(flow_tree)
