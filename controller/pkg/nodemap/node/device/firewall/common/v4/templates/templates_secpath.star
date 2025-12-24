# SecPath 防火墙模板配置 (Starlark 版本)
# 使用 Starlark 脚本定义各种配置对象的模板

def format_address_item(item, is_source):
    """格式化地址对象条目"""
    # 使用布尔属性判断类型
    if hasattr(item, "isRange") and item.isRange:
        return " range " + item.first + " " + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return " host address " + item.ip
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return " subnet " + item.ip + " " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return " range " + item.first + " " + item.last
        elif item.type == "HOST":
            return " host address " + item.ip
        elif item.type == "SUBNET":
            return " subnet " + item.ip + " " + item.mask.dotted
    # 最后回退：使用 cidr 格式
    elif hasattr(item, "cidr"):
        return " subnet " + item.cidr.replace("/", " ")
    return ""

def format_service_item(item):
    """格式化服务对象条目"""
    protocol = item.protocol
    result = "service " + protocol.lower
    
    if protocol.Equal("TCP") or protocol.Equal("UDP"):
        # 处理源端口
        if hasattr(item, "src_port") and not item.src_port.isFull:
            if item.src_port.count == 1:
                result += " source eq " + item.src_port.compact
            else:
                result += " source range " + item.src_port.first + " " + item.src_port.last
        # 处理目标端口 - 参考 v2 模板的逻辑
        if hasattr(item, "dst_port"):
            if item.dst_port.count == 1:
                result += " destination eq " + item.dst_port.compact
            elif not item.dst_port.isFull:
                result += " destination range " + item.dst_port.first + " " + item.dst_port.last
    elif protocol.Equal("ICMP"):    
        if hasattr(item, "hasType") and item.hasType:
            result += " type " + str(item.type)
            if hasattr(item, "hasCode") and item.hasCode:
                result += " code " + str(item.code)
    return result

def format_source_address(item):
    """格式化源地址"""
    # 使用布尔属性判断类型
    if hasattr(item, "isHost") and item.isHost:
        return "  source-ip-host " + item.ip
    elif hasattr(item, "isRange") and item.isRange:
        return "  source-ip-range " + item.first + " " + item.last
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "  source-ip-subnet " + item.ip + " " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "HOST":
            return "  source-ip-host " + item.ip
        elif item.type == "RANGE":
            return "  source-ip-range " + item.first + " " + item.last
        else:
            return "  source-ip-subnet " + item.ip + " " + item.mask.dotted
    # 最后回退：使用 cidr 格式
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return "  source-ip-subnet " + parts[0] + " " + parts[1]
    return "  source-ip-subnet " + item.ip + " " + item.mask.dotted

def format_destination_address(item):
    """格式化目标地址"""
    # 使用布尔属性判断类型
    if hasattr(item, "isHost") and item.isHost:
        return "  destination-ip-host " + item.ip
    elif hasattr(item, "isRange") and item.isRange:
        return "  destination-ip-range " + item.first + " " + item.last
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return "  destination-ip-subnet " + item.ip + " " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "HOST":
            return "  destination-ip-host " + item.ip
        elif item.type == "RANGE":
            return "  destination-ip-range " + item.first + " " + item.last
        else:
            return "  destination-ip-subnet " + item.ip + " " + item.mask.dotted
    # 最后回退：使用 cidr 格式
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return "  destination-ip-subnet " + parts[0] + " " + parts[1]
    return "  destination-ip-subnet " + item.ip + " " + item.mask.dotted

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group ip address " + meta["object_name"] + "\n"
    # 检查 is_source，支持字符串 "true"/"false" 和布尔值
    is_source = meta.get("is_source", False)
    # Starlark 不支持 isinstance，直接检查是否为字符串 "true" 或 "false"
    # 如果不是字符串，则假设是布尔值
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += " network" + format_address_item(item, is_source) + "\n"
    
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group ip address " + meta["object_name"] + "\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += " network group-object " + member + "\n"
    else:
        # 检查 is_source，支持字符串 "true"/"false" 和布尔值
        is_source = meta.get("is_source", False)
        # Starlark 不支持 isinstance，直接检查是否为字符串 "true" 或 "false"
        # 如果不是字符串，则假设是布尔值
        if is_source == "true" or is_source == "True":
            is_source = True
        elif is_source == "false" or is_source == "False":
            is_source = False
        network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
        for item in network_list:
            result += " network" + format_address_item(item, is_source) + "\n"
    
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group service " + meta["object_name"] + "\n"
    
    for item in intent.service.EachDetailed():
        result += " " + format_service_item(item) + "\n"
    
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group service " + meta["object_name"] + "\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += " service group-object " + member + "\n"
    
    return result

def render_address_group_add_member(intent, meta):
    """渲染地址组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""

    result = "object-group ip address " + group_name + "\n"

    # 从 intent.src 获取新地址（因为 generateAddressGroupUpdate 将新地址放在 src）
    # 或者从 intent.dst 获取新地址
    is_source = meta.get("is_source", False)
    # 支持字符串 "true"/"false" 和布尔值
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()

    for item in network_list:
        result += " network" + format_address_item(item, is_source) + "\n"

    return result

def render_service_group_add_member(intent, meta):
    """渲染服务组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""

    result = "object-group service " + group_name + "\n"

    # 从 intent.service 获取新服务
    for item in intent.service.EachDetailed():
        result += " " + format_service_item(item) + "\n"

    return result

def render_vip(intent, meta):
    """渲染VIP模板 - SecPath 不支持 VIP"""
    return ""

def render_mip(intent, meta):
    """渲染MIP模板 - SecPath 不支持 MIP"""
    return ""

def render_snat_pool(intent, meta):
    """渲染SNAT池模板"""
    pool_id = meta.get("pool_id", "")
    if not pool_id:
        return ""
    
    snat = meta.get("snat", "")
    return "nat address-group " + pool_id + "\n address " + snat + " " + snat + "\n"

def render_policy(intent, meta):
    """渲染安全策略模板"""
    result = "security-policy ip\n"
    if meta.get("is_reused"):
        result += " rule name " + meta.get("policy_name", "") + "\n"
    else:
        result += " rule " + str(meta.get("policy_id", "")) + " name " + meta.get("policy_name", "") + "\n"
    

    if not meta.get("is_reused"):
        for zone in meta.get("sourceZones", []):
            result += "  source-zone " + zone + "\n"
        
        for zone in meta.get("destinationZones", []):
            result += "  destination-zone " + zone + "\n"
        
    # 源地址
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "  source-ip " + item + "\n"
    else:
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            result += format_source_address(item) + "\n"
    
    # 目标地址
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "  destination-ip " + item + "\n"
    else:
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            result += format_destination_address(item) + "\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "  service " + item + "\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "  service-port ip\n"
        else:
            for item in intent.service.EachDetailed():
                protocol = item.protocol
                result += "  service-port " + protocol.lower
                
                if protocol.Equal("ICMP"):
                    if hasattr(item, "hasType") and item.hasType:
                        result += " type " + str(item.type)
                        if hasattr(item, "hasCode") and item.hasCode:
                            result += " code " + str(item.code)
                elif protocol.Equal("TCP") or protocol.Equal("UDP"):
                    if hasattr(item, "src_port") and not item.src_port.isFull:
                        if item.src_port.count == 1:
                            result += " source eq " + item.src_port.compact
                        else:
                            result += " source range " + item.src_port.first + " " + item.src_port.last
                    if hasattr(item, "dst_port") and not item.dst_port.isFull:
                        if item.dst_port.count == 1:
                            result += " destination eq " + item.dst_port.compact
                        else:
                            result += " destination range " + item.dst_port.first + " " + item.dst_port.last
                result += "\n"
    if not meta.get("is_reused"):
        result += "  action " + meta.get("action", "permit") + "\n"
        if not meta.get("enable", True):
            result += "  disable\n"
        if meta.get("description"):
            result += "  description " + meta["description"] + "\n"
    return result

def render_nat_policy(intent, meta):
    """渲染NAT策略模板"""
    nat_type = meta.get("nat_type", "")
    result = "nat global-policy\n"
    result += " rule name " + meta.get("nat_name", "") + "\n"
    
    if meta.get("description"):
        result += "  description " + meta["description"] + "\n"
    
    for zone in meta.get("sourceZones", []):
        result += "  source-zone " + zone + "\n"
    
    for zone in meta.get("destinationZones", []):
        result += "  destination-zone " + zone + "\n"
    
    # 源地址
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "  source-ip " + item + "\n"
    else:
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            result += format_source_address(item) + "\n"
    
    # 目标地址
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "  destination-ip " + item + "\n"
    else:
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            result += format_destination_address(item) + "\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "  service " + item + "\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "  service-port ip\n"
        else:
            for item in intent.service.EachDetailed():
                protocol = item.protocol
                result += "  service-port " + protocol.lower
                
                if protocol.Equal("ICMP"):
                    if hasattr(item, "hasType") and item.hasType:
                        result += " type " + str(item.type)
                        if hasattr(item, "hasCode") and item.hasCode:
                            result += " code " + str(item.code)
                elif protocol.Equal("TCP") or protocol.Equal("UDP"):
                    if hasattr(item, "src_port") and not item.src_port.isFull:
                        if item.src_port.count == 1:
                            result += " source eq " + item.src_port.compact
                        else:
                            result += " source range " + item.src_port.first + " " + item.src_port.last
                    if hasattr(item, "dst_port") and not item.dst_port.isFull:
                        if item.dst_port.count == 1:
                            result += " destination eq " + item.dst_port.compact
                        else:
                            result += " destination range " + item.dst_port.first + " " + item.dst_port.last
                result += "\n"
    
    # NAT动作
    if nat_type == "DNAT":
        if meta.get("vip_name"):
            result += "  action dnat object-group " + meta["vip_name"]
        else:
            result += "  action dnat ip-address " + intent.real_ip
        if intent.real_port:
            result += " local-port " + intent.real_port
        result += "\n"
    else:
        if meta.get("has_pool_id"):
            result += "  action snat address-group " + meta.get("pool_id", "") + "\n"
        elif meta.get("has_easy_ip"):
            result += "  action snat easy-ip\n"
        else:
            result += "  action snat ip-address " + intent.snat + "\n"
    
    return result

# 模板注册表
templates = {
    "SectionSeparator": "#",
    "AddressObject": render_address_object,
    "AddressGroup": render_address_group,
    "AddressGroupAddMember": render_address_group_add_member,
    "ServiceObject": render_service_object,
    "ServiceGroup": render_service_group,
    "ServiceGroupAddMember": render_service_group_add_member,
    "VIP": render_vip,
    "MIP": render_mip,
    "SnatPool": render_snat_pool,
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}
