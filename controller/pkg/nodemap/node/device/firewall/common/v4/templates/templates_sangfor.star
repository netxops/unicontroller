# Sangfor 防火墙模板配置 (Starlark 版本)
# 注意：Sangfor的ipentry使用CIDR格式（/24），不是点分十进制掩码

def format_sangfor_address_item(item):
    """格式化Sangfor地址条目"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return "ipentry " + item.first + "-" + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return "ipentry " + item.ip
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "ipentry " + item.ip + "/" + str(item.prefix)
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return "ipentry " + item.first + "-" + item.last
        elif item.type == "HOST":
            return "ipentry " + item.ip
        else:
            return "ipentry " + item.ip + "/" + str(item.prefix)
    # 最后回退：使用 cidr 或 ip + prefix
    elif hasattr(item, "cidr"):
        return "ipentry " + item.cidr
    elif hasattr(item, "prefix"):
        return "ipentry " + item.ip + "/" + str(item.prefix)
    return "ipentry " + item.ip

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config\n"
    result += "ipgroup \"" + meta["object_name"] + "\" ipv4\n"
    result += "type ip\n"
    result += "importance ordinary\n"
    
    # 统一处理is_source（支持字符串和布尔值）
    is_source = meta.get("is_source", False)
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += "    " + format_sangfor_address_item(item) + "\n"
    
    result += "end\n"
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config\n"
    result += "ipgroup \"" + meta["object_name"] + "\" ipv4\n"
    result += "type addrgroup\n"
    result += "importance ordinary\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "    member \"" + member + "\"\n"
    
    result += "end\n"
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config\n"
    result += "service \"" + meta["object_name"] + "\"\n"
    
    # TCP 服务
    for item in intent.service.TcpEach():
        if hasattr(item, "src_port") and not item.src_port.isFull:
            if item.src_port.count == 1:
                src_port_str = item.src_port.compact
            else:
                src_port_str = item.src_port.first + "-" + item.src_port.last
        else:
            src_port_str = "0-65535"
        
        if hasattr(item, "dst_port") and not item.dst_port.isFull:
            if item.dst_port.count == 1:
                dst_port_str = item.dst_port.compact
            else:
                dst_port_str = item.dst_port.first + "-" + item.dst_port.last
        else:
            dst_port_str = "0-65535"
        
        result += "    tcp src-port " + src_port_str + " dst-port " + dst_port_str + "\n"
    
    # UDP 服务
    for item in intent.service.UdpEach():
        if hasattr(item, "src_port") and not item.src_port.isFull:
            if item.src_port.count == 1:
                src_port_str = item.src_port.compact
            else:
                src_port_str = item.src_port.first + "-" + item.src_port.last
        else:
            src_port_str = "0-65535"
        
        if hasattr(item, "dst_port") and not item.dst_port.isFull:
            if item.dst_port.count == 1:
                dst_port_str = item.dst_port.compact
            else:
                dst_port_str = item.dst_port.first + "-" + item.dst_port.last
        else:
            dst_port_str = "0-65535"
        
        result += "    udp src-port " + src_port_str + " dst-port " + dst_port_str + "\n"
    
    # ICMP 服务
    for item in intent.service.IcmpEach():
        if hasattr(item, "hasType") and item.hasType:
            result += "    icmp type " + str(item.type)
            if hasattr(item, "hasCode") and item.hasCode:
                result += " code " + str(item.code)
            result += "\n"
        else:
            result += "    icmp type 255 code 255\n"
    
    # L3 协议
    for item in intent.service.L3Each():
        result += "    protocol " + str(item.protocol.number) + "\n"
    
    result += "end\n"
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "config\n"
    result += "servgroup \"" + meta["object_name"] + "\"\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "    service \"" + member + "\"\n"
    
    result += "end\n"
    return result

def render_policy(intent, meta):
    """渲染安全策略模板"""
    result = "config\n"
    result += "policy \"" + meta.get("policy_name", "") + "\" top\n"
    
    if meta.get("enable", True):
        result += "enable\n"
    
    result += "group \"default-policygroup\"\n"
    
    # 源区域
    for zone in meta.get("sourceZones", []):
        if zone != "":
            result += "    src-zone \"" + zone + "\"\n"
    
    # 目标区域
    for zone in meta.get("destinationZones", []):
        if zone != "":
            result += "    dst-zone \"" + zone + "\"\n"
    
    # 源地址（对象模式 vs 内联模式）
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "    src-ipgroup \"" + item + "\"\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "    src-ipgroup \"" + item.ip + "\"\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "    src-ipgroup \"" + item.first + "-" + item.last + "\"\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "    src-ipgroup \"" + item.ip + "\"\n"
                elif item.type == "RANGE":
                    result += "    src-ipgroup \"" + item.first + "-" + item.last + "\"\n"
                else:
                    prefix = item.prefix if hasattr(item, "prefix") else 32
                    result += "    src-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
            elif hasattr(item, "cidr"):
                result += "    src-ipgroup \"" + item.cidr + "\"\n"
            else:
                prefix = item.prefix if hasattr(item, "prefix") else 32
                result += "    src-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
    
    # 目标地址（对象模式 vs 内联模式）
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "    dst-ipgroup \"" + item + "\"\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "    dst-ipgroup \"" + item.ip + "\"\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "    dst-ipgroup \"" + item.first + "-" + item.last + "\"\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "    dst-ipgroup \"" + item.ip + "\"\n"
                elif item.type == "RANGE":
                    result += "    dst-ipgroup \"" + item.first + "-" + item.last + "\"\n"
                else:
                    prefix = item.prefix if hasattr(item, "prefix") else 32
                    result += "    dst-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
            elif hasattr(item, "cidr"):
                result += "    dst-ipgroup \"" + item.cidr + "\"\n"
            else:
                prefix = item.prefix if hasattr(item, "prefix") else 32
                result += "    dst-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "    service \"" + item + "\"\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "service \"any\"\n"
        else:
            result += "service \"any\"\n"
    
    result += "user-group \"/\"\n"
    result += "application \"全部\"\n"
    result += "action " + meta.get("action", "permit") + "\n"
    result += "schedule \"all-week\"\n"
    result += "log session-start disable\n"
    result += "log session-end disable\n"
    result += "end\n"
    
    return result

def render_nat_policy(intent, meta):
    """渲染NAT策略模板"""
    nat_type = meta.get("nat_type", "")
    
    if nat_type == "DNAT":
        result = "config\n"
        result += "  dnat-rule \"" + meta.get("nat_name", "") + "\" top\n"
    else:
        result = "config\n"
        result += "  snat-rule \"" + meta.get("nat_name", "") + "\" top\n"
    
    if meta.get("enable", True):
        result += "enable\n"
    
    if meta.get("fromZone"):
        result += "  src-zone \"" + meta["fromZone"] + "\"\n"
    
    result += "schedule \"all-week\"\n"
    
    # 源地址（对象模式 vs 内联模式）
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "    src-ipgroup \"" + item + "\"\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "    src-ipgroup \"" + item.ip + "\"\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "    src-ipgroup \"" + item.first + "-" + item.last + "\"\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "    src-ipgroup \"" + item.ip + "\"\n"
                elif item.type == "RANGE":
                    result += "    src-ipgroup \"" + item.first + "-" + item.last + "\"\n"
                else:
                    prefix = item.prefix if hasattr(item, "prefix") else 32
                    result += "    src-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
            elif hasattr(item, "cidr"):
                result += "    src-ipgroup \"" + item.cidr + "\"\n"
            else:
                prefix = item.prefix if hasattr(item, "prefix") else 32
                result += "    src-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
    
    # 目标地址（仅DNAT）
    if nat_type == "DNAT":
        # 内联模式：使用布尔属性判断类型
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "    dst-ip " + item.ip + "\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "    dst-ip " + item.first + "-" + item.last + "\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "    dst-ip " + item.ip + "\n"
                elif item.type == "RANGE":
                    result += "    dst-ip " + item.first + "-" + item.last + "\n"
                else:
                    prefix = item.prefix if hasattr(item, "prefix") else 32
                    result += "    dst-ip " + item.ip + "/" + str(prefix) + "\n"
            elif hasattr(item, "cidr"):
                result += "    dst-ip " + item.cidr + "\n"
            else:
                prefix = item.prefix if hasattr(item, "prefix") else 32
                result += "    dst-ip " + item.ip + "/" + str(prefix) + "\n"
        
        if meta.get("toZone"):
            result += "    dst-zone " + meta["toZone"] + "\n"
    else:
        # SNAT：目标地址（对象模式 vs 内联模式）
        if meta.get("has_destination_objects"):
            for item in meta.get("dst_objects", []):
                result += "    dst-ipgroup \"" + item + "\"\n"
        else:
            # 内联模式：使用布尔属性判断类型
            for item in intent.dst.EachDataRangeEntryAsAbbrNet():
                if hasattr(item, "isHost") and item.isHost:
                    result += "    dst-ipgroup \"" + item.ip + "\"\n"
                elif hasattr(item, "isRange") and item.isRange:
                    result += "    dst-ipgroup \"" + item.first + "-" + item.last + "\"\n"
                elif hasattr(item, "type"):
                    if item.type == "HOST":
                        result += "    dst-ipgroup \"" + item.ip + "\"\n"
                    elif item.type == "RANGE":
                        result += "    dst-ipgroup \"" + item.first + "-" + item.last + "\"\n"
                    else:
                        prefix = item.prefix if hasattr(item, "prefix") else 32
                        result += "    dst-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
                elif hasattr(item, "cidr"):
                    result += "    dst-ipgroup \"" + item.cidr + "\"\n"
                else:
                    prefix = item.prefix if hasattr(item, "prefix") else 32
                    result += "    dst-ipgroup \"" + item.ip + "/" + str(prefix) + "\"\n"
        
        if meta.get("toZone"):
            result += "    dst-zone " + meta["toZone"] + "\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "    service \"" + item + "\"\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "  service \"any\"\n"
        else:
            result += "  service \"any\"\n"
    
    # NAT动作
    if nat_type == "DNAT":
        if meta.get("has_mip_object"):
            result += "  transfer ipgroup " + meta.get("mip_object", "")
            if meta.get("has_real_port"):
                result += " port " + meta.get("real_port", "")
            result += "\n"
        else:
            result += "  transfer ip " + meta.get("real_ip", "")
            if meta.get("has_real_port"):
                result += " port " + meta.get("real_port", "")
            result += "\n"
    else:
        if meta.get("has_pool_id"):
            result += "  transfer ipgroup \"" + meta.get("pool_id", "") + "\"\n"
        else:
            result += "  transfer ip " + meta.get("snat", "") + "\n"
    
    result += "end\n"
    return result

# 模板注册表
templates = {
    "SectionSeparator": "\n",
    "AddressObject": render_address_object,
    "AddressGroup": render_address_group,
    "ServiceObject": render_service_object,
    "ServiceGroup": render_service_group,
    "VIP": lambda intent, meta: "",  # Sangfor 不支持 VIP
    "MIP": lambda intent, meta: "",  # Sangfor 不支持 MIP
    "SnatPool": lambda intent, meta: "",  # Sangfor 不支持独立 SNAT Pool
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}

