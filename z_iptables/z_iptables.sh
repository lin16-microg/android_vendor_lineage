#!/system/bin/sh

##
## IPTABLES / oem_out Custom Firewall Script for Android
##

# Variables, pointers to binaries
IPTABLES=/system/bin/iptables
IP6TABLES=/system/bin/ip6tables

##
## List of allowed apps to still connect to Google
##
list_apps() {
cat <<EOF
com.android.captiveportallogin
com.android.providers.downloads
com.aurora.store
com.firstrowria.pushnotificationtester
com.github.yeriomin.yalpstore
com.google.android.gms
com.netflix.mediaclient
com.vonglasow.michael.satstat
org.freeandroidtools.safetynettest
org.microg.gms.droidguard
org.schabi.newpipe
org.thoughtcrime.securesms
EOF
}

##
## Create IP(6)TABLES return statement for the Google exception
## (only if respective app from exception list is installed)
##
jump_app() {
APP_DIR="/data/data/$1"
if [ -d "$APP_DIR" ]; then
  APP_UID=`stat -c %u "$APP_DIR"`
  $IPTABLES -A 'oem_out' -m owner --uid-owner $APP_UID -j RETURN
  $IP6TABLES -A 'oem_out' -m owner --uid-owner $APP_UID -j RETURN
fi
}

##
## Flush OWN roles only
##
flush_oem() {
$IPTABLES -F 'oem_out'
$IP6TABLES -F 'oem_out'
}

##
## Own rules to block
##
do_block() {
# Reject outgoing IPv6 traffic to Facebook (w/o exception)
$IP6TABLES -A 'oem_out' -d 2620:0:1c00::/40 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a03:2880::/31 -j REJECT --reject-with icmp6-port-unreachable
# Reject outgoing IPv4 traffic to Facebook (w/o exception)
$IPTABLES -A 'oem_out' -d 31.13.24.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 31.13.64.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 45.64.40.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 45.172.103.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.220.144.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 69.63.176.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 69.171.224.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.119.76.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 102.132.96.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 103.4.96.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 129.134.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 157.240.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 157.240.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.252.64.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 179.60.192.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.60.216.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.89.218.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 204.15.20.0/22 -j REJECT --reject-with icmp-port-unreachable


# Shoot Google exceptions (app list)
list_apps | while read APP; do
  jump_app "$APP"
done
# Further exception for GPS (Test only)
$IPTABLES -A 'oem_out' -m owner --uid-owner 1021 -j RETURN

# Block outgoing IPv6 traffic to Google
$IP6TABLES -A 'oem_out' -d 2001:4860::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2404:6800::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2404:f340::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2600:1900::/28 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2607:f8b0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2620:33:c000::/48 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2620:120:e000::/40 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2800:3f0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a00:1450::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a00:79e1:805::/48 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2c0f:fb50::/32 -j REJECT --reject-with icmp6-port-unreachable
# Block outgoing IPv4 traffic to Google
$IPTABLES -A 'oem_out' -d 8.8.4.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.8.8.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.34.208.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.35.192.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 23.236.48.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 23.251.128.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 34.64.0.0/11 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 34.96.0.0/12 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 34.116.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 34.120.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.184.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.192.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.196.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.198.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.199.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.199.128.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.200.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.204.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.0.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.4.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.6.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.9.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.32.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.64.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.206.128.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.207.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.207.128.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.208.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.216.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.219.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.219.128.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.220.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.224.0.0/12 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.240.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.233.160.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.102.0.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.249.64.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 70.32.128.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 72.14.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.114.24.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.125.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.154.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.196.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 107.167.160.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 107.178.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.59.80.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.170.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.177.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 130.211.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.112.0.0/12 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 142.250.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 146.148.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 162.216.148.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 162.222.176.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.110.32.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.217.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.253.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.194.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.255.112.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 192.158.28.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 192.178.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 193.186.4.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.36.154.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.36.156.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.192.112.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.223.232.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 207.223.160.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.68.108.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.81.188.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 209.85.128.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.58.192.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.73.80.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.239.32.0/19 -j REJECT --reject-with icmp-port-unreachable
}

##
## If executed manually via command line, the system properties need
## to be set as well
##
set_prop() {
  PROP_STATE=$( getprop persist.privacy.iptab_blk )
  if [ "$PROP_STATE" != "$1" ]; then
      setprop persist.privacy.iptab_blk $1
  fi
}

##
## Main run
##
case "$1" in
  set)  flush_oem
        do_block
        set_prop 1
    ;;
  flush) flush_oem
         set_prop 0
    ;;
esac

