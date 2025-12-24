# DPTech 防火墙模板配置 (Starlark 版本)

def format_dptech_address_item(item, object_name):
    """格式化DPTech地址条目"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return "address-object " + object_name + " range " + item.first + " " + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return "address-object " + object_name + " " + item.cidr
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "address-object " + object_name + " " + item.cidr
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return "address-object " + object_name + " range " + item.first + " " + item.last
        else:
            return "address-object " + object_name + " " + item.cidr
    # 最后回退：使用 cidr
    elif hasattr(item, "cidr"):
        return "address-object " + object_name + " " + item.cidr
    return "address-object " + object_name + " " + item.ip + "/32"

def format_dptech_service_item(item, object_name):
    """格式化DPTech服务条目"""
    protocol = item.protocol
    result = "service-object " + object_name + " protocol " + protocol.lower
    
    if protocol.Equal("TCP") or protocol.Equal("UDP"):
        if hasattr(item, "src_port") and not item.src_port.isFull:
            if item.src_port.count == 1:
                result += " src-port " + item.src_port.compact
            else:
                result += " src-port " + item.src_port.first + " " + item.src_port.last
        if hasattr(item, "dst_port") and not item.dst_port.isFull:
            if item.dst_port.count == 1:
                result += " dst-port " + item.dst_port.compact
            else:
                result += " dst-port " + item.dst_port.first + " to " + item.dst_port.last
    elif protocol.Equal("ICMP"):
        if hasattr(item, "hasType") and item.hasType:
            result += " type " + str(item.type)
            if hasattr(item, "hasCode") and item.hasCode:
                result += " code " + str(item.code)
    
    return result

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    # 统一处理is_source（支持字符串和布尔值）
    is_source = meta.get("is_source", False)
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += format_dptech_address_item(item, meta["object_name"]) + "\n"
    
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "address-group " + meta["object_name"] + " address-object " + member + "\n"
    
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    for item in intent.service.EachDetailed():
        result += format_dptech_service_item(item, meta["object_name"]) + "\n"
    
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "service-group " + meta["object_name"] + " service-object " + member + "\n"
    
    return result

def render_address_group_add_member(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "address-group " + meta["object_name"] + " address-object " + member + "\n"
    
    return result

def render_service_group_add_member(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = ""
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "service-group " + meta["object_name"] + " service-object " + member + "\n"
    
    return result

def render_mip(intent, meta):
    """渲染MIP模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "address-pool " + meta["object_name"] + " address " + intent.dst.firstIP + " to " + intent.dst.lastIP + "\n"
    
    return result

def render_snat_pool(intent, meta):
    """渲染SNAT池模板"""
    pool_name = meta.get("pool_name", "")
    if not pool_name:
        return ""
    
    snat = meta.get("snat", "")
    result = "address-pool " + pool_name + " address " + snat + " to " + snat + "\n"
    
    return result

def render_policy(intent, meta):
    """渲染安全策略模板"""
    result = ""
    policy_name = meta.get("policy_name", "")
    fromZone = meta.get("fromZone", "")
    toZone = meta.get("toZone", "")
    
    # 源地址
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " src-address address-object " + item + "\n"
    
    # 目标地址
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " dst-address address-object " + item + "\n"
    
    # 服务
    if meta.get("is_ip_protocol", False):
        result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " service any\n"
    elif meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " service service-object " + item + "\n"
    else:
        for item in intent.service.EachDetailed():
            protocol = item.protocol
            if protocol.Equal("TCP") or protocol.Equal("UDP"):
                result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " service user-define-service " + protocol
                if hasattr(item, "dst_port") and not item.dst_port.isFull:
                    if item.dst_port.count == 1:
                        result += " dst-port " + item.dst_port.compact
                    else:
                        result += " dst-port " + item.dst_port.first + " to " + item.dst_port.last
                result += "\n"
            elif protocol.Equal("ICMP"):
                result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " service user-define-service ICMP\n"
    
    # 动作
    if not meta.get("is_reused"):
        result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " action " + meta.get("action", "permit") + "\n"
        
        # 描述
        if meta.get("description"):
            result += "security-policy " + policy_name + " src-zone " + fromZone + " dst-zone " + toZone + " description " + meta["description"] + "\n"
    
    return result

def render_nat_policy(intent, meta):
    """渲染NAT策略模板"""
    result = ""
    nat_name = meta.get("nat_name", "")

    # DNAT
    if meta.get("has_real_ip"):
        if meta.get("has_real_port"):
            fromPort = meta.get("fromPort", "")            
            interface = fromPort
            simplify_dst = intent.dst
            simplify_svc = intent.service

            if meta.get("mip_name"):
                result += "nat destination-nat " + nat_name + " interface " + interface + " global-address address-pool " + meta.get("mip_name")
                result += " service " + simplify_svc.protocol.lower + " "
                if simplify_svc.dst_port.count == 1:
                    result += simplify_svc.dst_port.compact
                else:
                    result += simplify_svc.dst_port.first + " to " + simplify_svc.dst_port.last
                result += " local-address " + intent.real_ip + " local-port " + intent.real_port + "\n"
            else:
                result += "nat destination-nat " + nat_name + " interface " + interface + " global-address " + simplify_dst.firstIP +  " local-address " + intent.real_ip + " local-port " + intent.real_port + "\n"
        else:
            fromPort = meta.get("fromPort", "")
            toPort = meta.get("toPort", "")
            real_ip = meta.get("real_ip", "")
            
            interface = fromPort if fromPort else toPort
            
            for item in intent.dst.EachDataRangeEntryAsAbbrNet():
                result += "nat static " + nat_name + " interface " + interface + " global-address " + item.ip + " local-address " + real_ip + "\n"
    else:
        # SNAT
        toPort = meta.get("toPort", "")
        if toPort:
            result += "nat source-nat " + nat_name + " interface " + toPort + "\n"
        
        # 源地址（对象模式 vs 内联模式）
        if meta.get("has_source_objects"):
            for item in meta.get("src_objects", []):
                result += "nat source-nat " + nat_name + " src-address address-object " + item + "\n"
        else:
            # 内联模式：使用布尔属性判断类型
            for item in intent.src.EachDataRangeEntryAsAbbrNet():
                if hasattr(item, "isHost") and item.isHost:
                    result += "nat source-nat " + nat_name + " src-address address-object " + item.ip + "\n"
                elif hasattr(item, "isRange") and item.isRange:
                    result += "nat source-nat " + nat_name + " src-address address-object " + item.first + "-" + item.last + "\n"
                elif hasattr(item, "type"):
                    if item.type == "HOST":
                        result += "nat source-nat " + nat_name + " src-address address-object " + item.ip + "\n"
                    elif item.type == "RANGE":
                        result += "nat source-nat " + nat_name + " src-address address-object " + item.first + "-" + item.last + "\n"
                    else:
                        result += "nat source-nat " + nat_name + " src-address address-object " + item.cidr + "\n"
                elif hasattr(item, "cidr"):
                    result += "nat source-nat " + nat_name + " src-address address-object " + item.cidr + "\n"
                else:
                    result += "nat source-nat " + nat_name + " src-address address-object " + item.ip + "/32\n"
        
        # 目标地址（对象模式 vs 内联模式）
        if meta.get("has_destination_objects"):
            for item in meta.get("dst_objects", []):
                result += "nat source-nat " + nat_name + " dst-address address-object " + item + "\n"
        else:
            # 内联模式：使用布尔属性判断类型
            for item in intent.dst.EachDataRangeEntryAsAbbrNet():
                if hasattr(item, "isHost") and item.isHost:
                    result += "nat source-nat " + nat_name + " dst-address address-object " + item.ip + "\n"
                elif hasattr(item, "isRange") and item.isRange:
                    result += "nat source-nat " + nat_name + " dst-address address-object " + item.first + "-" + item.last + "\n"
                elif hasattr(item, "type"):
                    if item.type == "HOST":
                        result += "nat source-nat " + nat_name + " dst-address address-object " + item.ip + "\n"
                    elif item.type == "RANGE":
                        result += "nat source-nat " + nat_name + " dst-address address-object " + item.first + "-" + item.last + "\n"
                    else:
                        result += "nat source-nat " + nat_name + " dst-address address-object " + item.cidr + "\n"
                elif hasattr(item, "cidr"):
                    result += "nat source-nat " + nat_name + " dst-address address-object " + item.cidr + "\n"
                else:
                    result += "nat source-nat " + nat_name + " dst-address address-object " + item.ip + "/32\n"
        
        # 服务（对象模式 vs 内联模式）
        if meta.get("has_service_objects"):
            for item in meta.get("service_objects", []):
                result += "nat source-nat " + nat_name + " service " + item + "\n"
        else:
            # IP协议特殊处理
            if meta.get("is_ip_protocol", False):
                result += "nat source-nat " + nat_name + " service any\n"
            else:
                result += "nat source-nat " + nat_name + " service any\n"
        
        # SNAT动作
        if meta.get("has_easy_ip"):
            result += "nat source-nat " + nat_name + " action use-interface\n"
        else:
            pool_name = meta.get("pool_name", "")
            result += "nat source-nat " + nat_name + " action address-pool " + pool_name + "\n"
        
        # 描述
        if meta.get("description"):
            result += "nat source-nat " + nat_name + " description " + meta["description"] + "\n"
    return result

# 模板注册表
templates = {
    "SectionSeparator": "!",
    "AddressObject": render_address_object,
    "AddressGroup": render_address_group,
    "AddressGroupAddMember": render_address_group_add_member,
    "ServiceObject": render_service_object,
    "ServiceGroup": render_service_group,
    "ServiceGroupAddMember": render_service_group_add_member,
    "VIP": lambda intent, meta: "",  # DPTech 不支持 VIP
    "MIP": render_mip,
    "SnatPool": render_snat_pool,
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}

