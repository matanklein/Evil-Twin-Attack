#!/usr/bin/env bash

# This script is used to set up the wireless interface for monitor mode
# Assuming the wireless interface is wlxe84e06aed7ca

sudo ifconfig wlxe84e06aed7ca down
sudo iwconfig wlxe84e06aed7ca mode Monitor
sudo ifconfig wlxe84e06aed7ca up
