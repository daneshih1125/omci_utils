#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

try:
    from omci.omcisemantic import OMCISemantic
except ImportError:
    pass


def ip_host_mode(value):
    if value & 0x1:
        return "DHCP"
    return "Static"


OMCISemantic.register(134, "IP options", ip_host_mode)
