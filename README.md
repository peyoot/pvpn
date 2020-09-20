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

Follow the instruction to select server/client mode and VPN type. You'll need to input public IP of VPN server. And then choose if you're installing VPN server (VPN Responder) or VPN client(VPN Initiator).
  
The scripts was designed as interactive one. But most of the time you only need to press Enter key. 



##### 1. Install and auto-configure VPN server
You need to have a VPS on cloud or have a server with public IP. If you don't have one, simply buy one from any cloud service provider like AWS/Azure/Alicloud. For example, any type of AWS EC2 or Lightsnail instance will just work fine. VPN server need to be deployed in Linux. Scripts have been tested with Ubuntu 16.04,18.04 and 20.04. Other version of Ubuntu or Debian may work but not garantee. 

##### EXAMPLE: Set up VPN server in AWS Lightsnail  
First, creat an instance of AWS Lightsnail. Select Linux/unix platform,OS only, Ubuntu 18.04 and choose a plan. Then create the instance. 
![](https://raw.githubusercontent.com/peyoot/pic_bed/master/imagesaws-lightsnail-1.PNG)

Once the instance has been created. Find the public IP of it and record it. You may need it later.

Click on the VPS's name and go to Networking tab to configure firewall  and add following rules:
> IPsec: UDP 500,4500
> Openvpn: TCP 8443,11000
> Webfs:8000
![](https://raw.githubusercontent.com/peyoot/pic_bed/master/images20200920071014.png)

Then go to connect tab, and connect it from web. Since the script may need to run a few while, it's better to run shell commands or scripts under tmux. 
```
ubuntu@ip-172-26-5-182:~$ tmux
```
If you close the browser accidentally You can resume the session later by "tmux attach".

Download PVPN and run install_vpn.sh as root:
```
ubuntu@ip-172-26-5-182:~$git clone https://github.com/peyoot/pvpn.git
Cloning into 'pvpn'...remote: Enumerating objects: 145, done.
remote: Counting objects: 100% (145/145), done.
remote: Compressing objects: 100% (102/102), done.remote: Total 770 (delta 47), reused 138 (delta 43), pack-reused 625
Receiving objects: 100% (770/770), 166.11 KiB | 351.00 KiB/s, done.
Resolving deltas: 100% (249/249), done.
ubuntu@ip-172-26-5-182:~$ cd pvpn
```
Now you can run the PVPN script to install VPN:

```
ubuntu@ip-172-26-5-182:~/pvpn$ sudo ./install_vpn.sh
Your ubuntu version is: 18.04
PVPN installation scripts  makes it easy to set up openvpn and strongswan in your own server and PC within NAT You can:
1. Install VPN server with public IP in the internet (press enter to accept this default)
2. Install VPN client on a PC in your home or office, so that it can set up VPN tunnel with the VPN server
3. Extend webfs service time on existing VPN Server so that client can download certifications from this server.
How are you going to install? [1]
```

Next one is to choose VPN Mode. By default Strongswan (IPSec)was seleted and you can press Enter to go next. Expert may choose to install OpenVPN solo or install both OpenVPN and Ipsec if they need. 

```
Select VPN server modeYou can:
1. Install openvpn+stunnel only and use easyrsa3 as PKI( enter to accept this default)
2. Install Strongswan only and use ipsec PKI tool
3. Install both strongswan and openvpn, use ipsec PKI tool Please choose which vpn type you're about to install? [2] 
```

And the next one goes to the place where you need to input server IP address. Input the correct one as you got from AWS management console.
```
Please input the server Public IP: []
```

The rest you can simply press Enter each time till script finish the installation.
Now you've got a VPN server installed.

##### 2. Install and configure VPN CLient
This vary from different platform on your devices:

Linux
---
Simply run
```
sudo install_vpn.sh
```
and choose to install VPN client in first selection tab. when it comes to input VPN server public IP address tab. Input the correct one. You'll just need to press Enter for other interactive selection. It will automatically install and download certs and configure VPN client for you.

Windows
---

  * Strongswan
Windows7 and Windows 10 can support IPSec IKEV2. You can open http://Server-IP:8000/pvpn/strongswan/ to download CA certification cacert.pem. 
Then [store it in trusted Root Authentication Authorities](https://wiki.strongswan.org/projects/strongswan/wiki/Win7EapCert). 

Then create an IPSEC IKEV2 VPN. Authentication using EAP-MSCHAP v2:
> username:robin password:pvpnpassword
You can change default username and password in conf file /etc/ipsec.secrects

 * OpenVPN
Install Openvpn and stunnel. Put the certs and conf file in right place.


Android
---
Install StrongSwan Client APP. Use cacert.pem as CA. and VPN type set as IKEV2 EAP.
Username: robin
Password: pvpnpassword
ServerID: server
ClientID: client

iPad
---



#### Reference for those install VPN server on your own geer:

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

#### Latest updates:
2020/9/11 

Now enable webfs access with default username and password (pvpn:download), For manually download you'll need to input username and password to avoid vulnerable, you can change default username and password in webfsd.conf


---

PVPN scripts is originally designed to simplify the palfort vpn set up and configuration process. Now you can take advantage of it to set up your own VPN network.
Palfort is an internet organization that aimed to gather people in the world to co-work together and build all necessary software and platform that you may need in "Internet Age". 

We believe as user and also as maker. We set up code and rules and also provide platforms, to prevent our future from kidnaped by internet gients like Google,Facebook,Amazon
You're welcome to join Palfort. More information please feel free to send an email to peyoot#hotmail.com
