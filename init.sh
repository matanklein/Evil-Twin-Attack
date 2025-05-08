#!/usr/bin/env bash

# This script is used to set up the wireless interface for monitor mode
# Assuming the wireless interface is wlxe84e06aed7ca

ifconfig wlxe84e06aed7ca down
iwconfig wlxe84e06aed7ca mode Monitor
ifconfig wlxe84e06aed7ca up