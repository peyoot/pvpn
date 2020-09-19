## PVPN is a tool to set up personal VPN

This scripts help user to set up and configure VPN. VPN is a critical tool to help you access resources that is banned or blocked by country like US,China or India.
For example, If you want to download or access Wechat, Tiktok in US or Inida, you may use VPN to set up encrypted tunnels between your Mobile/Pad/PC to a VPS outside of your current region. You won't be blocked as the service providers would see your devices as it was in the region that VPS located.

It support: openvpn and IPSec

* For openvpn it will use stunnel4 to hide the VPN tunnel into ssl so that it won't be blocked by China GFW.
* For strongswan, it help you configure server mode (with public IP) and client mode (initial connector). 

You can use on type of VPN or you can use both types of VPN in case you have some PC issues to prevent you from using specific VPN type.

### How to set up VPN
It's very simple as you can finish it in several minutes without any PC skills.
Basically, You'll need to set up a VPN server first. Scripts will help you generate  CA/Key/Certifications in the VPN server and also generate a temporary webpage for you to download the client certifications for your devices. 

The scripts was designed as interactive one. But most of the time you only need to press Enter key. 

##### 1. Install VPN server
You need to have a VPS on cloud or have a server with public IP. If you don't have one, simply buy one from any cloud service provider like AWS/Azure/Alicloud. For example, any type of AWS EC2 or Lightsnail instance will just work fine. VPN server need to be deployed in Linux. Scripts have been tested with Ubuntu 16.04,18.04 and 20.04. Other version of Ubuuntu or Debian may work but not garantee. 

##### EXAMPLE: Set up VPN server in AWS Lightsnail  
First, creat an instance of AWS Lightsnail. Select Linux/unix platform,OS only, Ubuntu 18.04 and choose a plan. Then create the instance. 

Once the instance has been created. Find the public IP of it and record it. You may need it later
Click on the VPS's name and go to Networking tab to configure firewall  and add following rules:
custom TCP: 8000,8443,11000
custom UDP: 500,4500

Then go to connect tab, and connect it from web. Since the script may need to run a few while, it's better to run in under tmux. 
''''shell
sudo apt update
tmux

Download the script and run it as root:





You need to install VPN server first which will help you generates all certifications that may needed. You can use these certifications in any client OS: linux ,Android,Mac, windows,etc.

Follow the instruction to select server/client mode and VPN type. You'll need to input public IP of VPN server. And then choose if you're installing VPN server (VPN Responder) or VPN client(VPN Initiator).
Most of the rest you only need to press "Enter" key follow the prompts if you don't know how to do it.  


PVPN scripts will help you generated every thing serer needed and also generated a client certification for the use in home or office PC/laptop. You can download client certs directly from server via web browser.
All necessary certs,config files,scripts in Ubuntu server/client will be generated in server and download & extract in client automatically.

Firewall:
Following ports need to be available in VPN server for scripts to function as expected:

TCP 8000  :  webfs port for downloading certs and configuration automatically.
TCP 8443  :  openvpn over stunnel, this is the port that stunnel4 service listen on
UDP 500,4500:  These two used by ipsec VPN. 

Scripts currently only support ubuntu 16.04 or 18.04, 20.04
After installation, to start the vpn in client PC:
For example in Linux PC:
For openvpn in ubuntu 18.04:  sudo systemctl start openvpn-client@client
For strongswan ipsec: ipsec up pvpn

Change Log:
2020/9/11 Now enable webfs access with default username and password (pvpn:download), For manually download you'll need to input username and password to avoid vulnerable, you can change default username and password in webfsd.conf



To do list:
----


PVPN scripts is originally designed to simplify the palfort vpn set up and configuration process. Now you can take advantage of it to set up your own VPN network.
Palfort is an internet organization that aimed to gather people in the world to co-work together and build all necessary software and platform that you may need in "Internet Age". 

We believe as user and also as maker. We set up code and rules and also provide platforms, to prevent our future from kidnaped by internet gients like Google,Facebook,Amazon
You're welcome to join Palfort. More information please feel free to send an email to peyoot#hotmail.com

