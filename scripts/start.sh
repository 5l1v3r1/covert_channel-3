#make the tun interface
sudo openvpn --mktun --dev tun2
#set the tun interface up
sudo ip link  set tun2 up
#set the ip address of the tun interface 
sudo ip addr add 10.0.0.2/24 dev tun2 
#set the MTU size of the tun interface
sudo ifconfig tun2 mtu 500

#create the wireless monitor interface for the interface which
#is used for injection
sudo iw phy phy0 interface add phy0 type monitor flags fcsfail 
#set the interface up
sudo ifconfig phy0 up

#create the wireless monitor interface for the interface which
#is used for a copy of wlan traffic transmitted
sudo iw phy phy1 interface add phy1 type monitor flags fcsfail
#set the interface up
sudo ifconfig phy1 up
#set the mtu of the interface to 1600 so that whole packet payload 
#to be modified before injection is copied
#default the mtu doesn't capture the whole frame
sudo ifconfig phy1 mtu 1600
