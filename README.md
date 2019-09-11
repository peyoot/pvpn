This scripts help user to set up and configure VPN. It support: openvpn and strongswan.
For openvpn it will use stunnel4 to hide the VPN tunnel into ssl so that it won't be block by GFW
For strongswan, it help you configure server mode (with public IP) and client mode (initial connector). 

All the scripts is to simplify the palfort vpn set up and configuration process. but you can take advantage from it to set up your own VPN network.
Palfort is an internet organization that aimed to gather people in the world to co-work together and build all necessary software and platform that you may need in "Internet Age". 

We believe as user and also as maker. We set up code and rules and also provide platforms, to prevent our future from kidnaped by internet gients like Google,Facebook,Amazon
 
You're welcome to join Palfort. More information please feel free to send an email



******examples*****
$>./pvpn_init -t openvpn -m client
or use latest scripts
$>./install_vpn.sh



***** updated in 2019 July****
To make it more simply and easy to use. We'll add an option to help customer build PKI and install both VPN server, generate an client RSA certification when user choose fast installation at the begining of the interactivities.
openvpn will also use strongswan PKI by default. For those who want to use openvpn only, we'll use latest EasyRSA 3 as PKI.
try with latest install scripts:  install_vpn.sh

