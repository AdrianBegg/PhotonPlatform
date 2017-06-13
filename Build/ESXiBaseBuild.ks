##########################################################################################
# Name: ESxi6BaseBuild.ks
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Date: 3/06/2017
# Purpose: A very basic Kickstart to perform a zero-touch install of ESXi 6.5 for use as
# a Photon Cloud Host
##########################################################################################
accepteula
install --firstdisk --preservevmfs
# Set the network to DHCP on the first network adapater
network --bootproto=dhcp --device=vmnic0
rootpw vmware123
reboot
