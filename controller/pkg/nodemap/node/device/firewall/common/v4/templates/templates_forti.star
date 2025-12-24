# FortiGate 防火墙模板配置 (Starlark 版本)

def format_forti_address_item(item):
    """格式化FortiGate地址条目"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return "        set type iprange\n            set start-ip " + item.first + "\n            set end-ip " + item.last + "\n"
    elif hasattr(item, "isHost") and item.isHost:
        return "        set subnet " + item.ip + " 255.255.255.255\n"
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "        set subnet " + item.ip + " " + item.mask + "\n"
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return "        set type iprange\n            set start-ip " + item.first + "\n            set end-ip " + item.last + "\n"
        elif item.type == "HOST":
            return "        set subnet " + item.ip + " 255.255.255.255\n"
        else:
            return "        set subnet " + item.ip + " " + item.mask + "\n"
    # 最后回退：使用 cidr 或 ip + mask
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return "        set subnet " + parts[0] + " " + item.mask + "\n"
    return "        set subnet " + item.ip + " " + item.mask + "\n"

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config firewall address\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    # 统一处理is_source（支持字符串和布尔值）
    is_source = meta.get("is_source", False)
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += format_forti_address_item(item)
    
    result += "    next\n"
    result += "end\n"
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config firewall addrgrp\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    if meta.get("member_objects"):
        member_list = []
        for member in meta["member_objects"]:
            member_list.append("\"" + member + "\"")
        result += "        set member " + " ".join(member_list) + "\n"
    
    result += "    next\n"
    result += "end\n"
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config firewall service custom\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    for item in intent.service.EachDetailed():
        protocol = item.protocol
        if protocol.Equal("TCP"):
            if hasattr(item, "dst_port") and not item.dst_port.isFull:
                if item.dst_port.count == 1:
                    result += "        set tcp-portrange " + item.dst_port.compact + "\n"
                else:
                    result += "        set tcp-portrange " + item.dst_port.first + "-" + item.dst_port.last + "\n"
        elif protocol.Equal("UDP"):
            if hasattr(item, "dst_port") and not item.dst_port.isFull:
                if item.dst_port.count == 1:
                    result += "        set udp-portrange " + item.dst_port.compact + "\n"
                else:
                    result += "        set udp-portrange " + item.dst_port.first + "-" + item.dst_port.last + "\n"
        elif protocol.Equal("ICMP"):
            if hasattr(item, "hasType") and item.hasType:
                result += "            set icmptype " + str(item.type) + "\n"
                if hasattr(item, "hasCode") and item.hasCode:
                    result += "                set icmpcode " + str(item.code) + "\n"
        else:
            result += "        set protocol-number " + str(item.protocol.number) + "\n"
    
    result += "    next\n"
    result += "end\n"
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config firewall service group\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    if meta.get("member_objects"):
        member_list = []
        for member in meta["member_objects"]:
            member_list.append("\"" + member + "\"")
        result += "        set member " + " ".join(member_list) + "\n"
    
    result += "    next\n"
    result += "end\n"
    return result

def render_vip(intent, meta):
    """渲染VIP模板"""
    if not meta.get("object_name") or meta.get("is_reused", False):
        return ""
    
    result = "config firewall vip\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    for item in intent.dst.EachDataRangeEntryAsAbbrNet():
        if item.type == "RANGE":
            result += "        set extip " + item.first + "-" + item.last + "\n"
        else:
            result += "        set extip " + item.ip + "\n"
    
    result += "        set mappedip \"" + meta.get("real_ip", "") + "\"\n"
    
    if meta.get("toPort"):
        result += "        set extintf \"" + meta["toPort"] + "\"\n"
    
    if meta.get("has_real_port"):
        result += "        set portforward enable\n"
        result += "        set extport " + meta.get("dst_port", "") + "\n"
        result += "        set mappedport " + meta.get("real_port", "") + "\n"
    else:
        result += "        set portforward disable\n"
    
    result += "    next\n"
    result += "end\n"
    return result

def render_mip(intent, meta):
    """渲染MIP模板"""
    if not meta.get("object_name") or meta.get("is_reused", False):
        return ""
    
    result = "config firewall vip\n"
    result += "    edit \"" + meta["object_name"] + "\"\n"
    
    for item in intent.dst.EachDataRangeEntryAsAbbrNet():
        result += "        set extip " + item.ip + "\n"
    
    result += "        set mappedip \"" + meta.get("real_ip", "") + "\"\n"
    result += "        set portforward disable\n"
    result += "    next\n"
    result += "end\n"
    return result

def render_snat_pool(intent, meta):
    """渲染SNAT池模板"""
    pool_name = meta.get("pool_name", "")
    if not pool_name or meta.get("is_reused", False):
        return ""
    
    result = "config firewall ippool\n"
    result += "    edit \"" + pool_name + "\"\n"
    result += "        set type overload\n"
    
    for item in intent.src.EachDataRangeEntryAsAbbrNet():
        if item.type == "RANGE":
            result += "        set startip " + item.first + "\n"
            result += "            set endip " + item.last + "\n"
        elif item.type == "HOST":
            result += "        set startip " + item.ip + "\n"
            result += "            set endip " + item.ip + "\n"
        else:
            result += "        set startip " + item.ip + "\n"
            result += "            set endip " + item.ip + "\n"
    
    result += "    next\n"
    result += "end\n"
    return result

def render_policy(intent, meta):
    """渲染安全策略模板"""
    result = "config firewall policy\n"
    result += "    edit " + str(meta.get("policy_id", "")) + "\n"
    result += "        set name \"" + meta.get("policy_name", "") + "\"\n"
    
    if meta.get("description"):
        result += "        set comments \"" + meta["description"] + "\"\n"
    
    if meta.get("fromPort"):
        result += "        set srcintf \"" + meta["fromPort"] + "\"\n"
    
    if meta.get("toPort"):
        result += "        set dstintf \"" + meta["toPort"] + "\"\n"
    
    # 源地址（对象模式 vs 内联模式）
    if meta.get("has_source_objects"):
        src_list = []
        for item in meta.get("src_objects", []):
            src_list.append("\"" + item + "\"")
        result += "        set srcaddr " + " ".join(src_list) + "\n"
    else:
        # 内联模式：FortiGate策略通常使用"all"，但也可以遍历生成内联地址
        result += "        set srcaddr \"all\"\n"
    
    # 目标地址（对象模式 vs 内联模式）
    if meta.get("has_destination_objects"):
        dst_list = []
        for item in meta.get("dst_objects", []):
            dst_list.append("\"" + item + "\"")
        result += "        set dstaddr " + " ".join(dst_list) + "\n"
    else:
        # 内联模式：FortiGate策略通常使用"all"，但也可以遍历生成内联地址
        result += "        set dstaddr \"all\"\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        svc_list = []
        for item in meta.get("service_objects", []):
            svc_list.append("\"" + item + "\"")
        result += "        set service " + " ".join(svc_list) + "\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "        set service \"ALL\"\n"
        else:
            result += "        set service \"ALL\"\n"
    
    result += "        set action " + meta.get("action", "accept") + "\n"
    result += "        set schedule \"always\"\n"
    if meta.get("enable", True):
        result += "        set status enable\n"
    else:
        result += "        set status disable\n"
    result += "    next\n"
    result += "end\n"
    
    return result

def render_nat_policy(intent, meta):
    """渲染NAT策略模板"""
    result = "config firewall policy\n"
    result += "    edit " + str(meta.get("policy_id", "")) + "\n"
    result += "        set name \"" + meta.get("policy_name", "") + "\"\n"
    
    if meta.get("description"):
        result += "        set comments \"" + meta["description"] + "\"\n"
    
    if meta.get("fromPort"):
        result += "        set srcintf \"" + meta["fromPort"] + "\"\n"
    
    if meta.get("toPort"):
        result += "        set dstintf \"" + meta["toPort"] + "\"\n"
    
    # 源地址
    if meta.get("has_source_objects"):
        src_list = []
        for item in meta.get("src_objects", []):
            src_list.append("\"" + item + "\"")
        result += "        set srcaddr " + " ".join(src_list) + "\n"
    else:
        result += "        set srcaddr \"all\"\n"
    
    # 目标地址
    if meta.get("has_destination_objects"):
        dst_list = []
        for item in meta.get("dst_objects", []):
            dst_list.append("\"" + item + "\"")
        result += "        set dstaddr " + " ".join(dst_list) + "\n"
    else:
        result += "        set dstaddr \"all\"\n"
    
    # 服务
    if meta.get("has_service_objects"):
        svc_list = []
        for item in meta.get("service_objects", []):
            svc_list.append("\"" + item + "\"")
        result += "        set service " + " ".join(svc_list) + "\n"
    else:
        result += "        set service \"ALL\"\n"
    
    result += "        set action " + meta.get("action", "accept") + "\n"
    
    # NAT配置
    if meta.get("has_real_ip"):
        result += "        set nat enable\n"
    else:
        if meta.get("use_pool"):
            result += "        set nat enable\n"
            result += "        set ippool enable\n"
            result += "        set poolname \"" + meta.get("pool_name", "") + "\"\n"
        else:
            result += "        set nat disable\n"
    
    result += "        set schedule \"always\"\n"
    result += "        set status enable\n"
    result += "    next\n"
    result += "end\n"
    
    return result

# 模板注册表
templates = {
    "SectionSeparator": "#",
    "AddressObject": render_address_object,
    "AddressGroup": render_address_group,
    "ServiceObject": render_service_object,
    "ServiceGroup": render_service_group,
    "VIP": render_vip,
    "MIP": render_mip,
    "SnatPool": render_snat_pool,
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}

