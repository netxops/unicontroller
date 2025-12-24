### 2025-05-30-08.47.23-132.252.148.65-NJ-GL4F-G16U5-FW.RP.M9010.txt

rule 4373 name GL4F-policy4373
  description NETACC_20250516_599902
  action pass
  source-zone QXDCN
  destination-zone QXBSS
  source-ip-host 132.254.115.92
  source-ip-host 132.254.115.102
  destination-ip-subnet 132.252.128.0 255.255.255.0
  destination-ip-subnet 132.252.142.0 255.255.255.0
  service-port tcp destination range 8000 10000

rule 4388 name GL4F-policy4388
  description NETACC_20250527_611713
  action pass
  source-zone QXDCN
  destination-zone QXMSS
  source-ip-subnet 132.254.32.0 255.255.255.0
  source-ip-subnet 132.254.98.0 255.255.255.0
  source-ip-subnet 132.254.115.0 255.255.255.0
  destination-ip-subnet 132.252.137.12 255.255.255.254
  service-port tcp destination eq 1621

rule 4390 name GL4F-policy4390
  description NETACC_20250528_612973
  action pass
  source-zone QXBD
  destination-zone QXDCN
  source-ip-host 132.252.145.116
  destination-ip-range 132.230.103.1 132.230.103.2
  service-port tcp destination eq 34532

rule 4391 name GL4F-policy4391
  description NETACC_20250529_614045
  action pass
  source-zone QXGUANKONG
  destination-zone QXDCN
  source-ip-host 132.252.138.127
  destination-ip-host 132.254.112.244
  service-port tcp destination eq 8111

---

 ip route-static default-preference 1

 ipv6 route-static default-preference 1

 ip route-static 0.0.0.0 0 Route-Aggregation12.1051 132.252.151.137 description DefaultRoute-TO_DCN
 ip route-static 132.224.69.64 26 Route-Aggregation12.1058 132.252.151.193 description For_GL4F_0Trust_Segment
 ip route-static 132.224.69.192 26 Route-Aggregation12.1058 132.252.151.193 description For_GL4F_0Trust_Segment
 ip route-static 132.224.70.0 26 Route-Aggregation12.1062 132.252.151.225 description GL4F_SEC_APP01
 ip route-static 132.224.70.64 28 Route-Aggregation12.1062 132.252.151.225 description GL4F_SEC_F5_VS01
 ip route-static 132.224.70.80 29 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_F5-GTM-VE
 ip route-static 132.224.70.88 29 Route-Aggregation12.1063 132.252.151.233 description GL4F_YINGJIAN_APP
 ip route-static 132.224.70.96 27 Route-Aggregation12.1062 132.252.151.225 description GL4F_SEC_DB01
 ip route-static 132.224.70.128 25 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_Trend_DS01
 ip route-static 132.224.71.0 25 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_CRM-KAFKA&ES
 ip route-static 132.224.71.128 25 Route-Aggregation12.1056 132.252.151.177 description GL4F_JIEKOU_APP03
 ip route-static 132.224.84.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_DB02
 ip route-static 132.224.85.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BILLING_APP03
 ip route-static 132.224.86.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_APP02
 ip route-static 132.224.87.0 24 Route-Aggregation12.1059 132.252.151.201 description GL4F_PCServer_Mgmt04
 ip route-static 132.224.88.0 24 Route-Aggregation12.1059 132.252.151.201 description GL4F_PCServer_Mgmt05
 ip route-static 132.224.89.0 25 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_XHZW_APP01
 ip route-static 132.224.89.128 26 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_XHZW_DB01
 ip route-static 132.224.89.192 26 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_XHZW_F5_VS01
 ip route-static 132.224.90.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BILLING_DB02
 ip route-static 132.224.91.0 26 Route-Aggregation12.1056 132.252.151.177 description GL4F_JIEKOU_F5_VS01
 ip route-static 132.228.127.248 29 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_GTM-VE(132.228.127.251)
 ip route-static 132.228.176.240 29 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_GTM(132.228.176.246)
 ip route-static 132.252.58.0 24 Route-Aggregation12.1058 132.252.151.193 description GL4F_0XinRen_QuDaoKeFu_VPN_Pool01
 ip route-static 132.252.59.0 24 Route-Aggregation12.1058 132.252.151.193 description GL4F_0XinRen_QuDaoKeFu_VPN_Pool02
 ip route-static 132.252.128.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_APP01
 ip route-static 132.252.129.0 25 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_DB01
 ip route-static 132.252.129.128 25 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_F5VS01
 ip route-static 132.252.130.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BILLING_APP01
 ip route-static 132.252.131.0 25 Route-Aggregation12.1052 132.252.151.145 description GL4F_BILLING_DB01
 ip route-static 132.252.131.128 25 Route-Aggregation12.1052 132.252.151.145 description GL4F_BILLING_F5VS01
 ip route-static 132.252.132.0 24 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_APP01
 ip route-static 132.252.133.0 25 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_DB01
 ip route-static 132.252.133.128 25 Route-Aggregation12.1053 132.252.151.153 description GL4F_OSS_F5_VS01
 ip route-static 132.252.134.0 24 Route-Aggregation12.1055 132.252.151.169 description GL4F_EDA_APP01
 ip route-static 132.252.135.0 25 Route-Aggregation12.1055 132.252.151.169 description GL4F_EDA_DB01
 ip route-static 132.252.135.128 25 Route-Aggregation12.1055 132.252.151.169 description GL4F_EDA_F5_VS01
 ip route-static 132.252.136.0 24 Route-Aggregation12.1054 132.252.151.161 description GL4F_MSS_APP01
 ip route-static 132.252.137.0 25 Route-Aggregation12.1054 132.252.151.161 description GL4F_MSS_DB01
 ip route-static 132.252.137.128 25 Route-Aggregation12.1054 132.252.151.161 description GL4F_MSS_F5_VS01
 ip route-static 132.252.138.0 24 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_APP01
 ip route-static 132.252.139.0 25 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_DB01
 ip route-static 132.252.139.128 25 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_F5_VS01
 ip route-static 132.252.140.0 24 Route-Aggregation12.1056 132.252.151.177 description GL4F_JIEKOU_APP01
 ip route-static 132.252.141.0 25 Route-Aggregation12.1057 132.252.151.185 description GL4F_LOCAL_APP01
 ip route-static 132.252.141.128 25 Route-Aggregation12.1057 132.252.151.185 description GL4F_LOCAL_DB01
 ip route-static 132.252.142.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_-BILLING_APP02
 ip route-static 132.252.143.0 24 Route-Aggregation12.1052 132.252.151.145 description GL4F_BSS_DOCKER01
 ip route-static 132.252.144.0 24 Route-Aggregation12.1056 132.252.151.177 description GL4F_JIEKOU_APP02
 ip route-static 132.252.145.0 24 Route-Aggregation12.1060 132.252.151.209 description GL4F_BD_PLATFORM01
 ip route-static 132.252.146.0 23 Route-Aggregation12.1059 132.252.151.201 description GL4F_PCServer_Mgmt01&02
 ip route-static 132.252.148.0 25 Route-Aggregation12.1059 132.252.151.201 description GL4F_NetworkDevice_Mgmt01
 ip route-static 132.252.148.128 25 Route-Aggregation12.1059 132.252.151.201 description GL4F_StorageDevice_Mgmt01
 ip route-static 132.252.149.0 24 Route-Aggregation12.1059 132.252.151.201 description GL4F_VmwareOS_Mgmt01
 ip route-static 132.252.150.0 24 Route-Aggregation12.1059 132.252.151.201 description GL4F_KVMOS_Mgmt01
 ip route-static 132.252.151.112 29 Route-Aggregation12.1059 132.252.151.201 description GL4F_F5-BIGIP-10000-default
 ip route-static 132.252.151.120 29 Route-Aggregation12.1060 132.252.151.209 description GL4F_RP-S12508_TO_BD-S12508
 ip route-static 132.252.151.248 29 Route-Aggregation12.1059 132.252.151.201 description For_S12508-TO-F5_LTM-VE
 ip route-static 132.252.152.0 24 Route-Aggregation12.1058 132.252.151.193 description GL4F_GUANKONG_KAFKA&ES01
 ip route-static 132.252.153.0 24 Route-Aggregation12.1059 132.252.151.201 description GL4F_PCServer_Mgmt03
 ip route-static 132.252.154.0 24 Route-Aggregation12.1061 132.252.151.217 description GL4F_SDN-VXLAN-TDS
 ip route-static 132.252.155.0 24 Route-Aggregation12.1061 132.252.151.217 description GL4F_SDN-VXLAN-Test
 ip route-static 132.254.240.0 20 Route-Aggregation12.1058 132.252.151.193 description For_GL_4F_VPN01_Segment01
 ip route-static vpn-instance VRF_GL_Management 132.224.0.0 11 132.252.148.1
 ipv6 route-static :: 0 Route-Aggregation12.1051 240E:1C7:8001:1:132:252:151:89 description v6DefaultRoute
 ipv6 route-static 240E:1C7:8001:10:: 60 Route-Aggregation12.1052 240E:1C7:8001:1:132:252:151:91 description GL4F_BSS-BSS_v6subnet
 ipv6 route-static 240E:1C7:8001:20:: 60 Route-Aggregation12.1052 240E:1C7:8001:1:132:252:151:91 description GL4F_BSS-BILLING_v6subnet
 ipv6 route-static 240E:1C7:8001:30:: 60 Route-Aggregation12.1053 240E:1C7:8001:1:132:252:151:99 description GL4F_OSS_v6subnet
 ipv6 route-static 240E:1C7:8001:40:: 60 Route-Aggregation12.1054 240E:1C7:8001:1:132:252:151:A1 description GL4F_MSS_v6subnet
 ipv6 route-static 240E:1C7:8001:50:: 60 Route-Aggregation12.1055 240E:1C7:8001:1:132:252:151:A9 description GL4F_EDA_v6subnet
 ipv6 route-static 240E:1C7:8001:60:: 60 Route-Aggregation12.1058 240E:1C7:8001:1:132:252:151:C1 description GL4F_GUANKONG_v6subnet
 ipv6 route-static 240E:1C7:8001:70:: 60 Route-Aggregation12.1062 240E:1C7:8001:1:132:252:151:E1 description GL4F_SEC_v6subnet
 ipv6 route-static 240E:1C7:8001:80:: 60 Route-Aggregation12.1057 240E:1C7:8001:1:132:252:151:B9 description GL4F_LOCAL_v6subnet
 ipv6 route-static 240E:1C7:8001:90:: 60 Route-Aggregation12.1056 240E:1C7:8001:1:132:252:151:B1 description GL4F_JIEKOU_v6subnet
 ipv6 route-static 240E:1C7:8001:B0:: 60 Route-Aggregation12.1060 240E:1C7:8001:1:132:252:151:D1 description GL4F_BD_v6subnet

---

### 2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt

rule name JiS_policy_2910
  description NETACC_20250528_612799
  source-zone QXDCN
  destination-zone QXEDA
  source-address range 132.254.168.18 132.254.168.21
  source-address range 132.254.168.23 132.254.168.30
  source-address range 132.254.168.32 132.254.168.41
  destination-address 132.252.33.42 0.0.0.0
  destination-address 132.252.33.110 0.0.0.0
  destination-address 132.252.33.117 0.0.0.0
  action permit

rule name JiS_policy_2913
  description NETACC_20250528_613629
  source-zone QXDCN
  destination-zone QXBSS
  source-address 132.252.12.0 mask 255.255.255.128
  destination-address 132.252.27.27 0.0.0.0
  service protocol tcp destination-port 8000 to 10000
  action permit
rule name JiS_policy_2914
  description NETACC_20250529_614045
  source-zone QXGUANKONG
  destination-zone QXDCN
  source-address 132.252.32.169 0.0.0.0
  destination-address 132.254.112.244 0.0.0.0
  service protocol tcp destination-port 8111
  action permit

---

132.252.37.0

132.254.168.18

1621 1625

132.252.37.0

32.224.2.0

---

ip route-static 0.0.0.0 0.0.0.0 Eth-Trunk2.10 132.252.19.65 description Default_Route-TO_DCN
ip route-static 10.254.45.64 255.255.255.240 Eth-Trunk2.14 132.252.19.97 description EDA_APP_JiTuan_02
ip route-static 132.224.69.0 255.255.255.192 Eth-Trunk2.15 132.252.19.105 description For_JiS_0Trust_Segment
ip route-static 132.224.69.128 255.255.255.192 Eth-Trunk2.15 132.252.19.105 description For_JiS_0Trust_Segment
ip route-static 132.224.160.0 255.255.240.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment06
ip route-static 132.228.185.0 255.255.255.0 Eth-Trunk2.21 132.252.19.169 description JiS-DMZ_02
ip route-static 132.252.19.160 255.255.255.248 Eth-Trunk2.21 132.252.19.169 description DMZ_12516-TO-DP
ip route-static 132.252.19.176 255.255.255.252 Eth-Trunk2.19 132.252.19.137 description NJ-JiS-E21/46U-SSW-1.M.CCS9032
ip route-static 132.252.19.184 255.255.255.248 Eth-Trunk2.19 132.252.19.137 description CONSOLE_JiS_IPS-LOG
ip route-static 132.252.19.248 255.255.255.248 Eth-Trunk2.15 132.252.19.105 description GUANKONG_GTM_DNS
ip route-static 132.252.24.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BSS_APP_01
ip route-static 132.252.25.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BSS_DB_01
ip route-static 132.252.26.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BSS_F5_VS_01
ip route-static 132.252.27.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BILLING_APP_01
ip route-static 132.252.28.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BILLING_DB_01
ip route-static 132.252.29.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BILLING_F5_VS_01
ip route-static 132.252.30.0 255.255.255.0 Eth-Trunk2.12 132.252.19.81 description OSS_APP_01
ip route-static 132.252.31.0 255.255.255.0 Eth-Trunk2.12 132.252.19.81 description OSS_DB_01
ip route-static 132.252.32.0 255.255.255.128 Eth-Trunk2.12 132.252.19.81 description OSS_F5_VS_01
ip route-static 132.252.32.128 255.255.255.128 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_02
ip route-static 132.252.33.0 255.255.255.0 Eth-Trunk2.14 132.252.19.97 description EDA_APP_01
ip route-static 132.252.34.0 255.255.255.128 Eth-Trunk2.14 132.252.19.97 description EDA_DB_01
ip route-static 132.252.34.128 255.255.255.128 Eth-Trunk2.14 132.252.19.97 description EDA_F5_VS_01
ip route-static 132.252.35.0 255.255.255.0 Eth-Trunk2.13 132.252.19.89 description MSS_APP_01
ip route-static 132.252.36.0 255.255.255.128 Eth-Trunk2.13 132.252.19.89 description MSS_DB_01
ip route-static 132.252.36.128 255.255.255.128 Eth-Trunk2.13 132.252.19.89 description MSS_F5_VS_01
ip route-static 132.252.37.0 255.255.255.128 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_01
ip route-static 132.252.37.128 255.255.255.192 Eth-Trunk2.15 132.252.19.105 description GUANKONG_DB_01
ip route-static 132.252.37.192 255.255.255.192 Eth-Trunk2.15 132.252.19.105 description GUANKONG_F5_VS_01
ip route-static 132.252.38.0 255.255.255.128 Eth-Trunk2.16 132.252.19.113 description SEC_APP_01
ip route-static 132.252.38.128 255.255.255.192 Eth-Trunk2.16 132.252.19.113 description SEC_DB_01
ip route-static 132.252.38.192 255.255.255.192 Eth-Trunk2.16 132.252.19.113 description SEC_F5_VS_01
ip route-static 132.252.39.0 255.255.255.128 Eth-Trunk2.17 132.252.19.121 description LOCAL_APP_01
ip route-static 132.252.39.128 255.255.255.128 Eth-Trunk2.17 132.252.19.121 description LOCAL_DB_01
ip route-static 132.252.40.0 255.255.255.128 Eth-Trunk2.18 132.252.19.129 description JIEKOU_APP_01
ip route-static 132.252.40.128 255.255.255.192 Eth-Trunk2.18 132.252.19.129 description JIEKOU_DB_01
ip route-static 132.252.40.192 255.255.255.192 Eth-Trunk2.18 132.252.19.129 description JIEKOU_F5_VS_01
ip route-static 132.252.41.0 255.255.255.128 Eth-Trunk2.11 132.252.19.73 description BILLING_Docker_01
ip route-static 132.252.42.0 255.255.255.0 Eth-Trunk2.19 132.252.19.137 description CONSOLE_VMwareOS_Management
ip route-static 132.252.43.0 255.255.255.128 Eth-Trunk2.20 132.252.19.145 description For_JiS_PaaS_TEST
ip route-static 132.252.43.128 255.255.255.128 Eth-Trunk2.18 132.252.19.129 description JIEKOU_SDS_01
ip route-static 132.252.44.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_DB_02
ip route-static 132.252.45.0 255.255.255.0 Eth-Trunk2.21 132.252.19.169 description JiS-DMZ_01
ip route-static 132.252.46.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_GUANKONG_PaaS_subassembly
ip route-static 132.252.48.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment01
ip route-static 132.252.56.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description JiS_0XinRen_QuDaoKeFu_VPN_Pool01
ip route-static 132.252.57.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description JiS_0XinRen_QuDaoKeFu_VPN_Pool02
ip route-static 132.252.60.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN_Segment05
ip route-static 132.252.61.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN_Segment06
ip route-static 132.252.62.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN_Segment07
ip route-static 132.252.63.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN_Segment08
ip route-static 132.252.64.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment01
ip route-static 132.252.65.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment02
ip route-static 132.252.66.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment03
ip route-static 132.252.67.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment04
ip route-static 132.252.68.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment05
ip route-static 132.252.69.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment06
ip route-static 132.252.70.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment07
ip route-static 132.252.71.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN02_Segment08
ip route-static 132.252.80.0 255.255.248.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment02
ip route-static 132.252.88.0 255.255.252.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment03
ip route-static 132.252.92.0 255.255.254.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment04
ip route-static 132.252.94.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_SSLVPN_Segment05
ip route-static 132.252.196.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_DB_03
ip route-static 132.252.197.0 255.255.255.128 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_04
ip route-static 132.252.197.128 255.255.255.128 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_05
ip route-static 132.252.198.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BILLING_DB_02
ip route-static 132.252.199.0 255.255.255.0 Eth-Trunk2.11 132.252.19.73 description BILLING_APP_02
ip route-static 132.252.204.0 255.255.255.128 Eth-Trunk2.14 132.252.19.97 description JiS_EDA_APP_03
ip route-static 132.252.204.128 255.255.255.128 Eth-Trunk2.15 132.252.19.105 description GUANKONG_DB_04
ip route-static 132.252.205.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_06
ip route-static 132.252.206.0 255.255.255.0 Eth-Trunk2.15 132.252.19.105 description GUANKONG_APP_07
ip route-static 132.252.254.0 255.255.255.128 Eth-Trunk2.22 132.252.19.193 description SDN_VXLAN-TDS
ip route-static 132.252.254.128 255.255.255.224 Eth-Trunk2.22 132.252.19.193 description SDN_VXLAN-TDS-VMmanage
ip route-static 132.252.254.160 255.255.255.240 Eth-Trunk2.22 132.252.19.193 description SDN_VXLAN-TDS-VMmanage
ip route-static 132.252.254.192 255.255.255.192 Eth-Trunk2.19 132.252.19.137 description CONSOLE_F5_VE_Manage
ip route-static 132.252.255.0 255.255.255.0 Eth-Trunk2.22 132.252.19.193 description SDN_VXLAN-TEST
ip route-static 132.254.64.0 255.255.240.0 Eth-Trunk2.15 132.252.19.105 description For_JiS_SangFor_VPN03_Segment01
ip route-static vpn-instance VPN_JiS_Management 132.224.0.0 255.224.0.0 GigabitEthernet0/0/0 132.252.20.1

---

### 2025-05-30-08.48.37-132.252.20.83-NJ-JiS-E19-FW-1.DMZ.DP1000.txt

address-object DCN_132.254.208.0/24 132.254.208.0/24

address-object JiS_DMZ_192.168.35.179 192.168.35.179/32

address-object DCN_SEC_DeepSearcher_01_policy02_addr01 range 132.254.168.15 132.254.168.41
address-object DCN_SEC_DeepSearcher_01_policy02_addr01 132.252.40.55/32

security-policy DCN_SEC_DeepSearcher_01_policy02 src-zone DCN dst-zone DMZ src-address address-object DCN_SEC_DeepSearcher_01_policy02_addr01
security-policy DCN_SEC_DeepSearcher_01_policy02 src-zone DCN dst-zone DMZ dst-address address-object JiS_DMZ_192.168.35.179
security-policy DCN_SEC_DeepSearcher_01_policy02 src-zone DCN dst-zone DMZ service user-define-service TCP dst-port 8989
security-policy DCN_SEC_DeepSearcher_01_policy02 src-zone DCN dst-zone DMZ action permit
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN src-address address-object JiS_DMZ_192.168.35.179
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN dst-address address-object DMZ_SEC_DeepSearcher_01_policy08_addr01
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN service user-define-service TCP dst-port 30000
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN service user-define-service TCP dst-port 30008
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN service user-define-service TCP dst-port 30707
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN action permit
security-policy DMZ_SEC_DeepSearcher_01_policy08 src-zone DMZ dst-zone DCN description NETACC_20250528_613388

---

ip route 0.0.0.0/0 bond11 132.252.19.161 description To-DCN
ip route 192.168.0.0/16 192.168.3.4 description DMZ-NET
ip route 132.224.0.0/11 meth0_9 132.252.20.1 vrf VRF_MGMT

---

### 2025-05-30-08.49.06-132.252.20.85-NJ-JiS-E16&17-FW-3.DMZ.F5000.txt

object-group ip address JiS_DMZ_690_src_addr01
 description JiS_DMZ_690_source_address
 0 network host address 172.16.148.140

rule 690 name JiS_DMZ_690
  description NETACC_20250521_605178
  action pass
  source-zone ZhuanXian
  destination-zone DMZ
  source-ip JiS_DMZ_690_src_addr01
  destination-ip 192.168.45.6
  service TCP_22
 rule 691 name JiS_DMZ_691
  description NETACC_20250521_604969
  action pass
  source-zone DMZ
  destination-zone 163
  source-ip JiS_DMZ_192.168.35.181

---

ip route-static 0.0.0.0 0 Reth5 192.168.254.5 description 163_DefaultRoute
 ip route-static 10.10.10.2 32 Reth3 192.168.0.4 description For_ZhuanXian_route01
 ip route-static 10.149.14.170 32 Reth4 192.168.1.4 description For_RZGLPT_CSJieKou01
 ip route-static 10.149.14.172 32 Reth4 192.168.1.4 description For_RZGLPT_CSJieKou01
 ip route-static 11.0.0.0 24 Reth3 192.168.0.4 description For_ZhuanXian_route_XuZhouFaYuan
 ip route-static 11.0.0.2 32 Reth3 192.168.0.4 description For_ZhuanXian_route_NanTongFaYuan
 ip route-static 15.0.48.10 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.11 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.12 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.13 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.14 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.15 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.0.48.16 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.1.165.5 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.1.165.7 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.1.165.8 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.1.165.9 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.5.194.81 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.5.194.82 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.5.194.83 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.5.194.84 32 Reth3 192.168.0.4 description For_ZhuanXian_CCB
 ip route-static 15.32.3.4 30 Reth3 192.168.0.4 description For_ZhuanXian_route25_JianSheYingHang02
 ip route-static 15.32.6.60 31 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route35
 ip route-static 17.32.32.32 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 17.32.32.48 32 Reth3 192.168.0.4 description For_ZhuanXian_route02
 ip route-static 17.32.32.58 32 Reth3 192.168.0.4 description For_ZhuanXian_route17_nongxinshe
 ip route-static 17.66.66.48 32 Reth3 192.168.0.4 description For_ZhuanXian_route03
 ip route-static 17.66.66.58 32 Reth3 192.168.0.4 description For_ZhuanXian_route04
 ip route-static 17.77.105.1 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 25.200.24.183 32 Reth3 192.168.0.4 description For_ZhuanXian_ChinaBank
 ip route-static 26.120.76.65 32 Reth3 192.168.0.4 description For_ZhongHang(ChinaBank)_Zhuanxian01#
 ip route-static 26.200.4.53 32 Reth3 192.168.0.4 description For_ZhuanXian_ZhongHang
 ip route-static 28.200.253.242 32 Reth3 192.168.0.4 description For_ZhongHang(ChinaBank)_Zhuanxian01#test
 ip route-static 32.0.193.60 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route34
 ip route-static 66.3.41.25 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 66.3.41.29 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 66.3.41.58 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 66.6.93.34 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 66.6.94.80 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 66.6.95.85 32 Reth3 192.168.0.4 description ZhuanXian_JSNSH_DaiKou
 ip route-static 88.40.6.34 32 Reth3 192.168.0.4 description For_ZhuanXian_route12
 ip route-static 88.40.6.36 32 Reth3 192.168.0.4 description For_ZhuanXian_route13
 ip route-static 88.40.32.13 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoHang
 ip route-static 88.40.32.15 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoHang
 ip route-static 88.40.32.23 32 Reth3 192.168.0.4 description For_ZhuanXian_route11
 ip route-static 88.40.32.151 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoShangYinHang
 ip route-static 88.40.32.153 32 Reth3 192.168.0.4 description For_ZhuanXian_route31
 ip route-static 88.40.32.177 32 Reth3 192.168.0.4 description For_ZhuanXian_route09
 ip route-static 88.40.32.178 32 Reth3 192.168.0.4 description For_ZhuanXian_route10
 ip route-static 88.40.64.137 32 Reth3 192.168.0.4 description For_ZhuanXian_route14
 ip route-static 88.40.89.10 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoHang
 ip route-static 88.40.89.20 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoShangYinHang
 ip route-static 88.40.89.21 32 Reth3 192.168.0.4 description ZhuanXian_ZhaoShangYinHang
 ip route-static 100.100.100.37 32 Reth3 192.168.0.4 description For_JiaoTongYinHang01#
 ip route-static 100.100.100.39 32 Reth3 192.168.0.4 description For_JiaoTongYinHang01#-3
 ip route-static 100.100.100.114 32 Reth3 192.168.0.4 description For_JiaoTongYinHang01#-4
 ip route-static 100.100.100.131 32 Reth3 192.168.0.4 description For_JiaoTongYinHang01#
 ip route-static 108.2.2.59 32 Reth3 192.168.0.4 description For_ZhuanXian_route15
 ip route-static 108.2.2.62 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.2.63 32 Reth3 192.168.0.4 description For_ZhuanXian_route15
 ip route-static 108.2.2.82 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.2.84 32 Reth3 192.168.0.4 description For_ZhuanXian_route22
 ip route-static 108.2.2.87 32 Reth3 192.168.0.4 description For_ZhuanXian_GongHang
 ip route-static 108.2.2.120 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.5.104 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.5.105 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.5.106 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.5.107 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.21.1 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.21.2 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.21.3 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.2.21.33 32 Reth3 192.168.0.4 description For_ZhuanXian_route20
 ip route-static 108.2.21.34 32 Reth3 192.168.0.4 description For_ZhuanXian_route21
 ip route-static 108.2.21.97 32 Reth3 192.168.0.4 description For_ZhuanXian_GongHang
 ip route-static 108.2.21.98 32 Reth3 192.168.0.4 description For_ZhuanXian_GongHang
 ip route-static 108.2.21.177 32 Reth3 192.168.0.4 description For_ZhuanXian_route18
 ip route-static 108.2.21.178 32 Reth3 192.168.0.4 description For_ZhuanXian_route19
 ip route-static 108.2.114.69 32 Reth3 192.168.0.4 description ZhuanXian_GongHang_DigitalCoin
 ip route-static 108.2.114.70 32 Reth3 192.168.0.4 description ZhuanXian_GongHang_DigitalCoin
 ip route-static 108.2.114.82 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.6.13.28 32 Reth3 192.168.0.4 description ZhuanXian_GongShangYinHang
 ip route-static 108.6.13.74 32 Reth3 192.168.0.4 description For_ZhuanXian_route15
 ip route-static 108.6.13.116 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.6.13.118 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.6.13.127 32 Reth3 192.168.0.4 description For_ZhuanXian_ICBC
 ip route-static 108.221.130.13 32 Reth3 192.168.0.4 description ZhuanXian_GongShangYinHang
 ip route-static 108.221.133.1 32 Reth3 192.168.0.4 description ZhuanXian_GongShangYinHang
 ip route-static 108.221.133.2 32 Reth3 192.168.0.4 description ZhuanXian_GongShangYinHang
 ip route-static 128.1.80.1 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route24
 ip route-static 128.1.80.2 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route26
 ip route-static 128.1.80.40 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route36
 ip route-static 128.1.80.41 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route32
 ip route-static 128.1.80.42 32 Reth3 192.168.0.4 description For_ZhuanXian_JianHang(CCB_Bank)_route33
 ip route-static 132.224.0.0 11 Reth4 192.168.1.4 description For_TO_DCN
 ip route-static 138.40.138.21 32 Reth3 192.168.0.4 description ZhuanXian_XingYeBank
 ip route-static 138.41.138.21 32 Reth3 192.168.0.4 description ZhuanXian_XingYeBank
 ip route-static 150.32.3.53 32 Reth3 192.168.0.4 description ZhuanXian_GuangFaBank
 ip route-static 150.32.3.72 32 Reth3 192.168.0.4 description ZhuanXian_GuangFaBank
 ip route-static 150.32.5.53 32 Reth3 192.168.0.4 description ZhuanXian_GuangFaBank
 ip route-static 150.32.5.58 32 Reth3 192.168.0.4 description ZhuanXian_GuangFaBank
 ip route-static 150.32.5.68 32 Reth3 192.168.0.4 description ZhuanXian_GuangFaBank
 ip route-static 172.16.49.107 32 Reth3 192.168.0.4 description ZhuanXian_PuFaBank
 ip route-static 172.16.100.16 30 Reth3 192.168.0.4 description For_ZhuanXian_route05
 ip route-static 172.16.148.140 32 Reth3 192.168.0.4 description ZhuanXian_PuFaBank
 ip route-static 192.168.0.14 32 Reth3 192.168.0.4 description For_ZhuanXian_route06
 ip route-static 192.168.0.40 30 Reth3 192.168.0.4 description For_ZhuanXian_ChangZhouFaYuan_route23
 ip route-static 192.168.0.44 30 Reth3 192.168.0.4 description For_ZhuanXian_ZhenJiangFaYuan
 ip route-static 192.168.2.0 23 Reth4 192.168.1.4 description For_DMZ_route01
 ip route-static 192.168.4.0 22 Reth4 192.168.1.4 description For_DMZ_route02
 ip route-static 192.168.8.0 21 Reth4 192.168.1.4 description For_DMZ_route03
 ip route-static 192.168.16.0 20 Reth4 192.168.1.4 description For_DMZ_route04
 ip route-static 192.168.20.0 24 Reth3 192.168.0.4 description For_ZhuanXian_route16_SuQianFaYuan
 ip route-static 192.168.32.0 19 Reth4 192.168.1.4 description For_DMZ_route05
 ip route-static 192.168.192.18 32 Reth3 192.168.0.4 description For_ZhuanXian_route29(NonHang01)
 ip route-static 192.168.192.27 32 Reth3 192.168.0.4 description For_ZhuanXian_route30(NonHang02)
 ip route-static 192.168.246.6 32 Reth3 192.168.0.4 description For_ZhuanXian_route08
 ip route-static 192.168.246.10 32 Reth3 192.168.0.4 description For_ZhuanXian_route27(YouChun03)
 ip route-static 192.168.246.13 32 Reth3 192.168.0.4 description For_ZhuanXian_route07
 ip route-static 192.168.246.101 32 Reth3 192.168.0.4 description For_ZhuanXian_route28(YouChun04)
 ip route-static 198.10.33.254 32 Reth3 192.168.0.4 description ZhuanXian_YouZhengDaiKou
 ip route-static 198.21.1.156 32 Reth3 192.168.0.4 description For_ZhongXinBanK_DaiKou
 ip route-static vpn-instance VPN_JiS_Management 132.224.0.0 11 132.252.20.1
 ipv6 route-static :: 0 Reth5 240E:978:D04:4::2 description IPv6_163_DefaultRoute
 ipv6 route-static 240E:978:D04💯: 56 Reth4 240E:978:D04:3::4 description JiS_DMZ_v6subnet

---

### 2025-05-30-08.49.40-132.239.180.12-CZ-LY-FW-1.BD.F5000.txt

object-group ip address 10.149.13.0/24
 0 network subnet 10.149.13.0 255.255.255.0

object-group service UDP_8104_8105_8106
 1 service udp destination eq 8104
 2 service udp destination eq 8105
 3 service udp destination eq 8106

object-group service UDP_8105_8106_8107
 1 service udp destination eq 8105
 2 service udp destination eq 8106
 3 service udp destination eq 8107

object-group service UDP_8106
 0 service udp destination eq 8106

object-group service UDP_8106-8113
 0 service udp destination range 8106 8113

rule 1236 name LY_policy_1236
  description NETACC_20250520_604005
  action pass
  source-zone QXBD
  destination-zone QXDCN
  source-ip 132.224.1.157
  source-ip 132.224.1.159
  source-ip CZLiY_132.224.1.161-163
  source-ip 132.224.1.165-167
  source-ip 132.224.1.169
  source-ip 132.224.1.174
  source-ip 132.224.40.39-43
  source-ip 132.224.40.69-74
  source-ip 132.224.40.99-104
  source-ip 132.224.41.26-33
  source-ip 132.224.41.53-54
  destination-ip LY_policy_1236_dst_addr01
  service TCP_8000
  service TCP_8443

CZLiY_132.224.1.59-63

  59-64

CZLiY_132.224.1.59-63_01

  59-63

rule 1237 name LY_policy_1237
  description NETACC_20250522_605405
  action pass
  source-zone QXBD
  destination-zone QXDCN
  source-ip 132.224.1.239
  source-ip 132.224.1.49-56
  source-ip CZLiY_132.224.1.59-63
  source-ip CZLiY_132.224.1.72-73
  source-ip CZLiY_132.224.1.79-80
  source-ip 132.224.201.8-9
  destination-ip LY_policy_1237_dst_addr01
  service TCP_1521

rule 1248 name LY_policy_1248
  description NETACC_20250528_612799
  action pass
  source-zone QXDCN
  destination-zone QXBD
  source-ip LY_policy_1248_src_addr01
  destination-ip 132.224.1.252
  service TCP_8800
 rule 1249 name LY_policy_1249
  description NETACC_20250528_612799
  action pass
  source-zone QXDCN
  destination-zone QXBD
  source-ip LY_policy_1249_src_addr01
  destination-ip CZLiY_132.224.1.246
  service TCP_9001
 rule 1250 name LY_policy_1250
  description NETACC_20250528_612799
  action pass
  source-zone QXDCN
  destination-zone QXBD
  source-ip LY_policy_1250_src_addr01
  destination-ip 132.224.1.33
 rule 1251 name LY_policy_1251
  description NETACC_20250529_614189
  action pass
  source-zone QXDCN
  destination-zone QXBD
  source-ip LY_policy_1251_src_addr01
  destination-ip 132.224.41.100
  service UDP_8702

---

ip route-static 0.0.0.0 0 Route-Aggregation14.100 132.224.0.37 description DefaultRoute-DCN
 ip route-static 132.224.0.52 30 Route-Aggregation14.102 132.224.0.45 description C2(2)/44U-SSW-1
 ip route-static 132.224.0.56 30 Route-Aggregation14.102 132.224.0.45 description CZLiY_IPS-LOG
 ip route-static 132.224.0.64 29 Route-Aggregation14.101 132.224.0.41 description TianYiYun
 ip route-static 132.224.1.0 24 Route-Aggregation14.101 132.224.0.41 description BD_JIEKOU_01
 ip route-static 132.224.2.0 24 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_01
 ip route-static 132.224.3.0 26 Route-Aggregation14.103 132.224.0.49 description LY_TDS_01
 ip route-static 132.224.3.128 25 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_06
 ip route-static 132.224.4.0 24 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_02
 ip route-static 132.224.5.0 24 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_03
 ip route-static 132.224.6.0 24 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_04
 ip route-static 132.224.7.0 24 Route-Aggregation14.102 132.224.0.45 description VMwareOS_Mgmt_01
 ip route-static 132.224.40.0 24 Route-Aggregation14.101 132.224.0.41 description BD_JIEKOU_02
 ip route-static 132.224.41.0 24 Route-Aggregation14.101 132.224.0.41 description BD_PLATFORM_05
 ip route-static 132.224.42.0 23 Route-Aggregation14.101 132.224.0.41 description TianYiYun02
 ip route-static 132.224.201.0 24 Route-Aggregation14.101 132.224.0.41 description CZLiY_TYY
 ip route-static 132.224.207.0 24 Route-Aggregation14.101 132.224.0.41 description CZLiY_TYY
 ip route-static vpn-instance VPN_LY_Management 132.224.0.0 11 132.239.180.1

---

### 2025-05-30-08.50.14-132.254.194.222-DP1000-容灾备份-仪征403.txt

security-policy iboc_policy_20250521_2 src-zone Untrust dst-zone Trust src-address address-object iboc_policy_20250521_2_src_addr01
security-policy iboc_policy_20250521_2 src-zone Untrust dst-zone Trust dst-address address-object iboc_YiZ_132.254.96.38-40
security-policy iboc_policy_20250521_2 src-zone Untrust dst-zone Trust service user-define-service TCP dst-port 12182
security-policy iboc_policy_20250521_2 src-zone Untrust dst-zone Trust action permit
security-policy iboc_policy_20250521_2 src-zone Untrust dst-zone Trust description NETACC_20250521_604920
security-policy iboc_policy_20250521_3 src-zone Untrust dst-zone Trust src-address address-object iboc_policy_20250521_3_src_addr01
security-policy iboc_policy_20250521_3 src-zone Untrust dst-zone Trust dst-address address-object iboc_YiZ_132.254.98.10-51
security-policy iboc_policy_20250521_3 src-zone Untrust dst-zone Trust service any
security-policy iboc_policy_20250521_3 src-zone Untrust dst-zone Trust action permit
security-policy iboc_policy_20250521_3 src-zone Untrust dst-zone Trust description NETACC_20250521_604920
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust src-address address-object iboc_policy_20250523_1_src_addr01
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust dst-address address-object iboc_YiZ_132.254.98.20-51
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust dst-address address-object iboc_YiZ_132.254.98.160-204
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust service any
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust action permit
security-policy iboc_policy_20250523_1 src-zone Untrust dst-zone Trust description NETACC_20250523_608111
security-policy iboc_policy_20250527_1 src-zone Untrust dst-zone Trust src-address address-object iboc_policy_20250527_1_src_addr01
security-policy iboc_policy_20250527_1 src-zone Untrust dst-zone Trust dst-address address-object iboc_YiZ_132.254.98.19
security-policy iboc_policy_20250527_1 src-zone Untrust dst-zone Trust service user-define-service TCP dst-port 28433
security-policy iboc_policy_20250527_1 src-zone Untrust dst-zone Trust action permit
security-policy iboc_policy_20250527_1 src-zone Untrust dst-zone Trust description NETACC_20250527_611520

---

ip route 0.0.0.0/0 vlan-if1208 192.167.255.19
ip route 132.254.96.0/22 vlan-if1209 192.167.254.19
ip route 0.0.0.0/0 meth0_0 132.254.194.254 vrf mgmt

---

### 2025-05-30-08.51.12-132.254.160.136-C8U31-FW-1.DCN.Edu1000E-仪征303.txt

rule name YiZ303_policy_1116
  description NETACC_20250507_589437
  source-zone QXTEST
  destination-zone QXDCN
  source-address 132.254.168.0 mask 255.255.255.0
  destination-address 132.252.188.17 0.0.0.0
  service protocol tcp destination-port 29888
  action permit

rule name YiZ303_policy_1117
  description NETACC_20250522_605777
  source-zone QXTEST
  destination-zone QXDCN
  source-address range 132.254.168.18 132.254.168.41
  destination-address range 132.254.87.210 132.254.87.212
  service protocol tcp destination-port 20000 to 40000
  action permit

rule name YiZ303_policy_1129
  description NETACC_20250527_611828
  source-zone QXDCN
  destination-zone QXTEST
  source-address range 132.254.12.246 132.254.12.247
  destination-address range 132.254.167.64 132.254.167.65
  destination-address range 132.254.167.72 132.254.167.73
  destination-address 132.254.167.87 0.0.0.0
  destination-address 132.254.167.95 0.0.0.0
  service protocol tcp destination-port 9000 to 9099
  action permit

rule name YiZ303_policy_1132
  description NETACC_20250528_612799
  source-zone QXTEST
  destination-zone QXDCN
  source-address range 132.254.168.18 132.254.168.21
  source-address range 132.254.168.23 132.254.168.30
  source-address range 132.254.168.32 132.254.168.41
  destination-address 10.2.14.162 0.0.0.0
  service protocol tcp destination-port 6000
  service protocol tcp destination-port 6002
  action permit

---

ip route-static 0.0.0.0 0.0.0.0 Eth-Trunk21.101 132.254.164.9 description For_DCN_Default_Route
ip route-static 132.254.164.128 255.255.255.248 Eth-Trunk21.105 132.254.164.41 description IPS_LOG
ip route-static 132.254.165.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_APP01
ip route-static 132.254.166.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_DB01
ip route-static 132.254.167.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_PAAS01
ip route-static 132.254.168.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_DOCKER01
ip route-static 132.254.169.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_F5_01
ip route-static 132.254.170.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_APP01
ip route-static 132.254.171.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_APP02
ip route-static 132.254.172.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_DB01
ip route-static 132.254.173.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_DB02
ip route-static 132.254.174.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_PAAS01
ip route-static 132.254.175.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_PAAS02
ip route-static 132.254.176.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_DOCKER01
ip route-static 132.254.177.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_DOCKER02
ip route-static 132.254.178.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_F5_01
ip route-static 132.254.179.0 255.255.255.0 Eth-Trunk21.103 132.254.164.25 description For_BACKUP_F5_02
ip route-static 132.254.180.0 255.255.255.0 Eth-Trunk21.104 132.254.164.33 description For_PROD_APP01
ip route-static 132.254.181.0 255.255.255.0 Eth-Trunk21.104 132.254.164.33 description For_PROD_DB01
ip route-static 132.254.182.0 255.255.255.0 Eth-Trunk21.104 132.254.164.33 description For_PROD_PAAS01
ip route-static 132.254.183.0 255.255.255.0 Eth-Trunk21.104 132.254.164.33 description For_PROD_DOCKER01
ip route-static 132.254.184.0 255.255.255.0 Eth-Trunk21.104 132.254.164.33 description For_PROD_F5_01
ip route-static 132.254.185.0 255.255.255.0 Eth-Trunk21.105 132.254.164.41 description For_VT_CONSOLE01
ip route-static 132.254.186.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_APP02
ip route-static 132.254.187.0 255.255.255.0 Eth-Trunk21.102 132.254.164.17 description For_TEST_APP03
ip route-static vpn-instance VPN_YiZ_Management 132.224.0.0 255.224.0.0 GigabitEthernet0/0/0 132.254.160.129

---

### 2025-05-30-08.51.44-132.254.194.188-H3C-F5K-DMZ-仪征403.txt

 rule 1010 name YiZ_DMZ_policy010
  description NETACC_20241115_462670
  action pass
  source-zone DMZ
  destination-zone 163
  source-ip YiZ_DMZ_192.168.22.113
  destination-ip YiZ_DMZ_policy010_dst_addr01
  service TCP_8443
 rule 1011 name YiZ_DMZ_policy011
  description NETACC_20241212_487508
  action pass
  source-zone 163
  destination-zone DMZ
  destination-ip YiZ_DMZ_192.168.35.172
  service TCP_5443
  service TCP_43210
  service TCP_8002
  service ping

---

ip route-static 0.0.0.0 0 192.167.255.11
 ip route-static 192.168.0.0 16 192.167.254.11
 ip route-static vpn-instance management 0.0.0.0 0 132.254.194.254

---

### 2025-05-30-08.52.17-132.254.194.190-DP1000-DMZ-仪征403.txt

address-object YiZ403DCN_SEC_MobileAPPGW_RZBB_policy04_addr01 132.252.197.192/26
address-object YiZ403DCN_SEC_MobileAPPGW_RZBB_policy04_addr01 range 132.252.206.78 132.252.206.82

security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust src-address address-object YiZ403DMZ_192.168.35.155
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust src-address address-object YiZ403DMZ_192.168.35.156
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust src-address address-object YiZ403DMZ_192.168.35.157
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust src-address address-object YiZ403DMZ_192.168.35.158
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust dst-address address-object YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170_addr01
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust service user-define-service TCP dst-port 80
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust service user-define-service TCP dst-port 443
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust service user-define-service TCP dst-port 30024
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust action permit
security-policy YiZ403DMZ_SEC_MobileAPPGW_RZBB_policy170 src-zone Trust dst-zone Untrust description NETACC_20250522_605512
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust src-address address-object DMZ_132.254.211.0/25
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust src-address address-object DMZ_192.168.0.0/16
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust dst-address address-object NETACC_20250523_608078_policy01_dst_addr01
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust service user-define-service TCP dst-port 8422
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust service user-define-service TCP dst-port 8423
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust action permit
security-policy NETACC_20250523_608078_policy01 src-zone Trust dst-zone Untrust description NETACC_20250523_608078

---

ip route 10.0.0.0/8 bond2.1201 192.167.255.3 description 出访CN2
ip route 132.0.0.0/8 bond2.1201 192.167.255.3 description 出访DCN
ip route 132.254.211.0/25 bond2.1202 192.167.254.3 description exsi存储带内管理
ip route 192.168.0.0/16 bond2.1202 192.167.254.3 description 业务私网
ip route 0.0.0.0/0 gige0_7 132.254.194.254 vrf mgmt

---

### 2025-05-30-08.52.49-132.254.63.254-tyy-fw-M9010-吉山5号楼702.txt

rule 8982 name 20250529_58

  action pass
  source-zone DCN
  destination-zone TYY_JS_BILLING
  source-ip-host 132.252.229.77
  source-ip-host 132.252.229.87
  destination-ip-host 132.254.10.166
  service-port tcp destination eq 18921

 rule 8983 name 20250529_59
  action pass
  source-zone TYY_JS_GK
  destination-zone DCN
  source-ip-host 132.254.29.48
  source-ip-host 132.254.29.49
  source-ip-host 132.254.29.50
  source-ip-host 132.254.29.70
  destination-ip-host 132.254.194.192
  destination-ip-host 132.254.194.193
  destination-ip-host 132.254.194.220
  destination-ip-host 132.254.194.221
  service-port tcp destination eq 22
  service-port tcp destination eq 443
 rule 8984 name 20250529_60
  action pass
  source-zone DCN
  destination-zone TYY_JS_EDA
  source-ip-host 132.254.168.15
  destination-ip-host 132.254.22.141
  service-port tcp destination eq 81

---

动态路由

---
