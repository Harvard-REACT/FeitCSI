#!/bin/bash

sudo modprobe -r iwlmvm iwlwifi mac80211 cfg80211 rtw88_8822bu 2> /dev/null
sudo modprobe rtw88_8822bu 2> /dev/null
sudo modprobe iwlwifi 2> /dev/null
sleep 1
ifconfig
iw dev
sudo rfkill list