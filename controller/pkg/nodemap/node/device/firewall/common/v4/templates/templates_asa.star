# ASA 防火墙模板配置 (Starlark 版本)

def format_asa_address_item(item):
    """格式化ASA地址条目"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return "range " + item.first + " " + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return "host " + item.ip
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "subnet " + item.ip + " " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return "range " + item.first + " " + item.last
        elif item.type == "HOST":
            return "host " + item.ip
        else:
            return "subnet " + item.ip + " " + item.mask.dotted
    # 最后回退：使用 cidr 或 ip + mask
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return "subnet " + parts[0] + " " + item.mask.dotted
    return "subnet " + item.ip + " " + item.mask.dotted

def format_asa_service_item(item):
    """格式化ASA服务条目"""
    protocol = item.protocol
    result = "service " + protocol.lower
    
    if protocol.Equal("TCP") or protocol.Equal("UDP"):
        if hasattr(item, "src_port") and not item.src_port.isFull:
            result += " source range " + item.src_port.first + " " + item.src_port.last
        if hasattr(item, "dst_port") and not item.dst_port.isFull:
            if item.dst_port.count == 1:
                result += " destination eq " + item.dst_port.compact
            else:
                result += " destination range " + item.dst_port.first + " " + item.dst_port.last
    elif protocol.Equal("ICMP"):
        if hasattr(item, "hasType") and item.hasType:
            result += " " + str(item.type) + " " + str(item.code)
    
    return result

def format_asa_network_object(item):
    """格式化ASA网络对象"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return " network-object range " + item.first + " " + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return " network-object host " + item.ip
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return " network-object " + item.ip + " " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return " network-object range " + item.first + " " + item.last
        elif item.type == "HOST":
            return " network-object host " + item.ip
        else:
            return " network-object " + item.ip + " " + item.mask.dotted
    # 最后回退：使用 cidr 或 ip + mask
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return " network-object " + parts[0] + " " + item.mask.dotted
    return " network-object " + item.ip + " " + item.mask.dotted

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object network " + meta["object_name"] + "\n"
    
    # 统一处理is_source（支持字符串和布尔值）
    is_source = meta.get("is_source", False)
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += "  " + format_asa_address_item(item) + "\n"
    
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group network " + meta["object_name"] + "\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "  network-object object " + member + "\n"
    
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object service " + meta["object_name"] + "\n"
    
    for item in intent.service.EachDetailed():
        result += "  " + format_asa_service_item(item) + "\n"
    
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group service " + meta["object_name"] + "\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "  service-object object " + member + "\n"
    
    return result

def render_address_group_add_member(intent, meta):
    """渲染地址组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""
    
    result = "object-group network " + group_name + "\n"
    
    # 从 intent.src 获取新地址（因为 generateAddressGroupUpdate 将新地址放在 src）
    # ASA 地址组添加成员使用 network-object 命令
    for item in intent.src.EachDataRangeEntryAsAbbrNet():
        # 检查是否是单个地址对象（需要先创建对象）还是直接使用地址
        # 这里简化处理，直接使用地址格式
        if hasattr(item, "isRange") and item.isRange:
            result += "  network-object range " + item.first + " " + item.last + "\n"
        elif hasattr(item, "isHost") and item.isHost:
            result += "  network-object host " + item.ip + "\n"
        elif hasattr(item, "isNetwork") and item.isNetwork:
            result += "  network-object " + item.ip + " " + item.mask.dotted + "\n"
        else:
            # 回退到 format_asa_address_item
            result += "  network-object " + format_asa_address_item(item) + "\n"
    
    return result

def render_service_group_add_member(intent, meta):
    """渲染服务组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""
    
    result = "object-group service " + group_name + "\n"
    
    # 从 intent.service 获取新服务
    for item in intent.service.EachDetailed():
        result += "  " + format_asa_service_item(item) + "\n"
    
    return result

def render_mip(intent, meta):
    """渲染MIP模板"""
    if not meta.get("object_name") or meta.get("is_reused", False):
        return ""
    
    result = "object network " + meta["object_name"] + "\n"
    fromPort = meta.get("fromPort", "")
    toPort = meta.get("toPort", "")
    real_ip = meta.get("real_ip", "")
    
    # 构建接口对
    if fromPort and toPort:
        interface_pair = "(" + fromPort + "," + toPort + ")"
    elif fromPort:
        interface_pair = "(" + fromPort + ",any)"
    elif toPort:
        interface_pair = "(any," + toPort + ")"
    else:
        interface_pair = "(any,any)"
    
    for item in intent.dst.EachDataRangeEntryAsAbbrNet():
        result += "  nat " + interface_pair + " static " + item.ip + " " + real_ip + "\n"
    
    result += "\n"
    return result

def render_snat_pool(intent, meta):
    """渲染SNAT池模板"""
    pool_name = meta.get("pool_name", "")
    if not pool_name or meta.get("is_reused", False):
        return ""
    
    result = "object-group network " + pool_name + "\n"
    
    for item in intent.src.EachDataRangeEntryAsAbbrNet():
        result += "    " + format_asa_network_object(item) + "\n"
    
    return result

def render_policy(intent, meta):
    """渲染安全策略模板（ASA使用ACL）"""
    result = ""
    policy_name = meta.get("policy_name", "")
    action = meta.get("action", "permit")
    
    # IP协议特殊处理
    if meta.get("is_ip_protocol", False):
        # IP协议：使用any
        protocol_str = "ip"
        src_str = "any"
        dst_str = "any"
        if meta.get("has_source_objects"):
            src_obj = meta.get("src_objects", [])
            src_str = "object-group " + src_obj[0] if src_obj else "any"
        if meta.get("has_destination_objects"):
            dst_obj = meta.get("dst_objects", [])
            dst_str = "object-group " + dst_obj[0] if dst_obj else "any"
        result += "    access-list " + policy_name + " extended " + action + " " + protocol_str + " " + src_str + " " + dst_str + "\n"
        return result
    
    # ASA使用intent.items()遍历所有组合
    for item in intent.items():
        # 协议
        if meta.get("has_service_objects"):
            svc_obj = meta.get("service_objects", [])
            if len(svc_obj) > 0:
                protocol_str = "object-group " + svc_obj[0]
            else:
                protocol_str = item.service.protocol.lower
        else:
            protocol_str = item.service.protocol.lower
        
        # 源地址（对象模式 vs 内联模式）
        if meta.get("has_source_objects"):
            src_obj = meta.get("src_objects", [])
            src_str = "object-group " + src_obj[0] if src_obj else "any"
        else:
            # 内联模式：使用布尔属性判断
            if hasattr(item.src, "isFull") and item.src.isFull:
                src_str = "any"
            elif hasattr(item.src, "isHost") and item.src.isHost:
                src_str = "host " + item.src.ip
            elif hasattr(item.src, "isRange") and item.src.isRange:
                src_str = "range " + item.src.first + " " + item.src.last
            elif hasattr(item.src, "type"):
                if item.src.type == "HOST":
                    src_str = "host " + item.src.ip
                elif item.src.type == "RANGE":
                    src_str = "range " + item.src.first + " " + item.src.last
                else:
                    src_str = item.src.ip + " " + item.src.mask.dotted
            else:
                src_str = item.src.ip + " " + item.src.mask.dotted
        
        # 目标地址（对象模式 vs 内联模式）
        if meta.get("has_destination_objects"):
            dst_obj = meta.get("dst_objects", [])
            dst_str = "object-group " + dst_obj[0] if dst_obj else "any"
        else:
            # 内联模式：使用布尔属性判断
            if hasattr(item.dst, "isFull") and item.dst.isFull:
                dst_str = "any"
            elif hasattr(item.dst, "isHost") and item.dst.isHost:
                dst_str = "host " + item.dst.ip
            elif hasattr(item.dst, "isRange") and item.dst.isRange:
                dst_str = "range " + item.dst.first + " " + item.dst.last
            elif hasattr(item.dst, "type"):
                if item.dst.type == "HOST":
                    dst_str = "host " + item.dst.ip
                elif item.dst.type == "RANGE":
                    dst_str = "range " + item.dst.first + " " + item.dst.last
                else:
                    dst_str = item.dst.ip + " " + item.dst.mask.dotted
            else:
                dst_str = item.dst.ip + " " + item.dst.mask.dotted
        
        # 端口（仅TCP/UDP，内联模式时）
        port_str = ""
        dst_port_str = ""
        if not meta.get("has_service_objects"):
            protocol = item.service.protocol
            if protocol.Equal("TCP") or protocol.Equal("UDP"):
                if hasattr(item.service, "src_port") and not item.service.src_port.isFull:
                    if item.service.src_port.count == 1:
                        port_str = " eq " + item.service.src_port.compact
                    else:
                        port_str = " range " + item.service.src_port.first + " " + item.service.src_port.last
                if hasattr(item.service, "dst_port") and not item.service.dst_port.isFull:
                    if item.service.dst_port.count == 1:
                        dst_port_str = " eq " + item.service.dst_port.compact
                    else:
                        dst_port_str = " range " + item.service.dst_port.first + " " + item.service.dst_port.last
            elif protocol.Equal("ICMP"):
                if hasattr(item.service, "hasType") and item.service.hasType:
                    dst_port_str = " icmp-type " + str(item.service.type)
                    if hasattr(item.service, "hasCode") and item.service.hasCode:
                        dst_port_str += " icmp-code " + str(item.service.code)
        
        result += "    access-list " + policy_name + " extended " + action + " " + protocol_str + " " + src_str + " " + dst_str + port_str + dst_port_str + "\n"
    
    return result

def render_nat_policy(intent, meta):
    if meta.get("nat_style") == "twice":
        return render_twice_nat_policy(intent, meta)
    if meta.get("nat_style") == "object":
        return render_object_nat_policy(intent, meta)
    # 默认使用 twice nat
    return render_twice_nat_policy(intent, meta)

def render_object_nat_policy(intent, meta):
    """渲染Object NAT策略模板"""
    result = ""
    nat_type = meta.get("nat_type", "")
    fromPort = meta.get("fromPort", "")
    toPort = meta.get("toPort", "")
    fromZones = meta.get("sourceZones", ["UNKNOWN_SOURCE_ZONE"])
    toZones = meta.get("destinationZones", ["UNKNOWN_DESTIONATION_ZONE"])

    if not fromPort or not toPort:
        return result

    if nat_type == "DNAT":
        # DNAT Object NAT: 在 real_ip 对应的对象内定义 NAT
        # object network <real_ip_object>
        #   nat (<from_zone>,<to_zone>) static <mapped_ip_object> [service <protocol> <real_port> <mapped_port>]
        
        dst_obj = meta.get("dst_objects", [])
        mip_name = meta.get("mip_name", "")
        
        if not dst_obj or not mip_name:
            return result
        
        # Object NAT 的接口顺序：real_ifc 是 to_zone (inside), mapped_ifc 是 from_zone (outside)
        # 格式: nat (inside, outside) static <mapped_ip_object>
        # 对于 DNAT，需要反转顺序：从 (outside, inside) 转为 (inside, outside)
        nat_pair = "(" + toZones[0] + "," + fromZones[0] + ")"
        
        # Object NAT 是在 real_ip 对应的对象（mip_name）内定义的，映射到 mapped_ip 对应的对象（dst_obj[0]）
        result = "object network " + mip_name + "\n"
        result += "  nat " + nat_pair + " static " + dst_obj[0]
        
        # 如果有端口映射，添加 service 子句
        if intent.real_port:
            # 获取协议
            protocol = "tcp"  # 默认
            if intent.service:
                for item in intent.service.EachDetailed():
                    if hasattr(item, "protocol"):
                        protocol = item.protocol.lower
                        break
            
            # 获取映射后的端口（从 intent.service 中获取）
            mapped_port = ""
            if intent.service:
                for item in intent.service.EachDetailed():
                    if hasattr(item, "dst_port") and not item.dst_port.isFull:
                        if item.dst_port.count == 1:
                            mapped_port = item.dst_port.compact
                        else:
                            mapped_port = item.dst_port.first + " " + item.dst_port.last
                        break
            
            if mapped_port:
                result += " service " + protocol + " " + intent.real_port + " " + mapped_port
        
        result += "\n"
        
    else:
        # SNAT Object NAT: 在源对象内定义 NAT
        # object network <real_src_object>
        #   nat (<from_zone>,<to_zone>) dynamic <snat_target>
        
        src_obj = meta.get("src_objects", [])
        src_list = src_obj if src_obj else []
        
        if not src_list:
            return result
        
        # Object NAT 的接口顺序：real_ifc 是 from_zone (inside), mapped_ifc 是 to_zone (outside)
        nat_pair = "(" + fromZones[0] + "," + toZones[0] + ")"
        
        for src in src_list:
            result += "object network " + src + "\n"
            
            if meta.get("has_pool_id"):
                pool_id = meta.get("pool_id", "")
                result += "  nat " + nat_pair + " dynamic pat-pool " + pool_id
            elif meta.get("has_interface_name"):
                result += "  nat " + nat_pair + " dynamic interface"
            elif meta.get("snat"):
                snat = meta.get("snat", "")
                result += "  nat " + nat_pair + " dynamic " + snat
            else:
                # 默认使用 interface
                result += "  nat " + nat_pair + " dynamic interface"
            
            result += "\n"
    
    return result


def render_twice_nat_policy(intent, meta):
    """渲染NAT策略模板（Twice NAT）"""
    result = ""
    nat_type = meta.get("nat_type", "")
    fromPort = meta.get("fromPort", "")
    toPort = meta.get("toPort", "")
    fromZones = meta.get("sourceZones", ["UNKNOWN_SOURCE_ZONE"])
    toZones = meta.get("destinationZones", ["UNKNOWN_DESTIONATION_ZONE"])

    if not fromPort or not toPort:
        return result

    if nat_type == "DNAT":
        # DNAT: source static + destination static

        src_obj = meta.get("src_objects", ["UNKNOWN_SRC"])
        dst_obj = meta.get("dst_objects", ["UNKNOWN_DST"])
        svc_obj = meta.get("service_objects", ["UNKNOWN_SERVICE"])
        real_port_obj = meta.get("real_port_service_object", ["UNKNOWN_REALPORT_OBJECT"])
        intent_reverse_svs_obj = meta.get("intent_reverse_service_object", ["UNKNOWN_INTENT_REVERSE_SVS_OBJECT"])
        mip_name = meta.get("mip_name", "")

        nat_pair = "(" + toZones[0] + "," + fromZones[0] + ")"
        #source_pair = " source static " + src_obj[0] + " " + src_obj[0]
        #destination_pair = " destination static " + dst_obj[0] + " " + mip_name 
        destination_pair = " destination static " + src_obj[0] + " " + src_obj[0]
        source_pair = " source static " + mip_name + " " + dst_obj[0]
        if intent.real_port:
            service_pair = " service " + real_port_obj[0] + " " + intent_reverse_svs_obj[0]
        else:
            service_pair = ""
       # result += "nat " + nat_pair +  + + " " + service_pair + "\n"
        result = "nat " + nat_pair + source_pair + destination_pair + service_pair

	# nat [(real_ifc,mapped_ifc)] [line | {after-object [line]}] source static real_ob [mapped_obj | interface [ipv6]] [destination static {mapped_obj | interface [ipv6]} real_obj] [service real_src_mapped_dest_svc_obj mapped_src_real_dest_svc_obj] [net-to-net] [dns] [unidirectional | no-proxy-arp] [inactive] [description desc]
	# nat (inside,outside) source static 0.0.0.0/0 0.0.0.0/0 destination static 203.0.113.100 10.1.1.100 service TCP_80 TCP_8080
    else:
        # SNAT: source dynamic + destination static (如果有 destination_pair)
        nat_pair = "(" + fromZones[0] + "," + toZones[0] + ")"
        src_obj = meta.get("src_objects", [])
        src_list = src_obj if src_obj else ["any"]
        svc_obj = meta.get("service_objects", ["UNKNOWN_SERVICE"])
        dst_obj = meta.get("dst_objects", [])
        has_destination = meta.get("has_destination_objects", False) and len(dst_obj) > 0
        service_pair = " service " + svc_obj[0] + " " + svc_obj[0] + "\n"
        
        # 构建 destination_pair（如果有目标对象）
        destination_pair = ""
        if has_destination:
            destination_pair = " destination static " + dst_obj[0] + " " + dst_obj[0]
        
        if meta.get("has_pool_id"):
            pool_id = meta.get("pool_id", "")
            for src in src_list:
                result += "nat " + nat_pair + " source dynamic " + src + " pat-pool " + pool_id + destination_pair
        elif meta.get("has_interface_name"):
            for src in src_list:
                result += "nat " + nat_pair + " source dynamic " + src + " interface" + destination_pair
        elif meta.get("snat"):
            snat = meta.get("snat", "")
            for src in src_list:
                result += "nat " + nat_pair + " source dynamic " + src + " " + snat + destination_pair

        result += service_pair
    
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
    "VIP": lambda intent, meta: "",  # ASA 不支持 VIP
    "MIP": render_mip,
    "SnatPool": render_snat_pool,
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}

