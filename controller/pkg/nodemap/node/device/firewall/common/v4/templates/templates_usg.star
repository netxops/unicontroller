# USG 防火墙模板配置 (Starlark 版本)

def format_usg_address_item(item):
    """格式化USG地址条目"""
    # 使用布尔属性判断类型（优先级最高）
    if hasattr(item, "isRange") and item.isRange:
        return " address range " + item.first + " " + item.last
    elif hasattr(item, "isHost") and item.isHost:
        return " address " + item.ip + " mask 255.255.255.255"
    elif hasattr(item, "isNetwork") and item.isNetwork:
        return " address " + item.ip + " mask " + item.mask.dotted
    # 回退：尝试使用 type 属性（字符串）
    elif hasattr(item, "type"):
        if item.type == "RANGE":
            return " address range " + item.first + " " + item.last
        elif item.type == "HOST":
            return " address " + item.ip + " mask 255.255.255.255"
        else:
            return " address " + item.ip + " mask " + item.mask.dotted
    # 最后回退：使用 cidr 或 ip + mask
    elif hasattr(item, "cidr"):
        parts = item.cidr.split("/")
        if len(parts) == 2:
            return " address " + parts[0] + " mask " + item.mask.dotted
    return " address " + item.ip + " mask " + item.mask.dotted

def format_usg_service_item(item):
    """格式化USG服务条目"""
    protocol = item.protocol
    result = "service protocol " + protocol.lower
    
    if protocol.Equal("TCP") or protocol.Equal("UDP"):
        if hasattr(item, "src_port") and not item.src_port.isFull:
            if item.src_port.count == 1:
                result += " source-port " + item.src_port.compact
            else:
                result += " source-port " + item.src_port.first + " to " + item.src_port.last
        if hasattr(item, "dst_port") and not item.dst_port.isFull:
            if item.dst_port.count == 1:
                result += " destination-port " + item.dst_port.compact
            else:
                result += " destination-port " + item.dst_port.first + " to " + item.dst_port.last
    elif protocol.Equal("ICMP"):
        if hasattr(item, "hasType") and item.hasType:
            result += " icmp-type " + str(item.type)
            if hasattr(item, "hasCode") and item.hasCode:
                result += " " + str(item.code)
    
    return result

def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "ip address-set " + meta["object_name"] + " type object\n"
    
    # 统一处理is_source（支持字符串和布尔值）
    is_source = meta.get("is_source", False)
    if is_source == "true" or is_source == "True":
        is_source = True
    elif is_source == "false" or is_source == "False":
        is_source = False
    
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += format_usg_address_item(item) + "\n"
    
    return result

def render_address_group(intent, meta):
    """渲染地址组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "ip address-set " + meta["object_name"] + " type group\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "    address address-set " + member + "\n"
    else:
        # 统一处理is_source（支持字符串和布尔值）
        is_source = meta.get("is_source", False)
        if is_source == "true" or is_source == "True":
            is_source = True
        elif is_source == "false" or is_source == "False":
            is_source = False
        
        network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
        
        for item in network_list:
            result += format_usg_address_item(item) + "\n"
    
    return result

def render_service_object(intent, meta):
    """渲染服务对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "ip service-set " + meta["object_name"] + " type object\n"
    
    for item in intent.service.EachDetailed():
        result += " " + format_usg_service_item(item) + "\n"
    
    return result

def render_service_group(intent, meta):
    """渲染服务组模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "ip service-set " + meta["object_name"] + " type group\n"
    
    if meta.get("member_objects"):
        for member in meta["member_objects"]:
            result += "    service service-set " + member + "\n"
    
    return result

def render_address_group_add_member(intent, meta):
    """渲染地址组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""

    result = "ip address-set " + group_name + " type group\n"

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
        result += format_usg_address_item(item) + "\n"

    return result

def render_service_group_add_member(intent, meta):
    """渲染服务组添加成员模板（用于增强复用）"""
    group_name = meta.get("group_name") or meta.get("object_name")
    if not group_name:
        return ""

    result = "ip service-set " + group_name + " type group\n"

    # 从 intent.service 获取新服务
    for item in intent.service.EachDetailed():
        result += " " + format_usg_service_item(item) + "\n"

    return result

def render_mip(intent, meta):
    """渲染MIP模板"""
    if not meta.get("object_name") or meta.get("is_reused", False):
        return ""
    
    result = "destination-nat address-group " + meta["object_name"] + " 0\n"
    result += "section " + intent.real_ip + " " + intent.real_ip + "\n"
    return result

def render_snat_pool(intent, meta):
    """渲染SNAT池模板"""
    pool_id = meta.get("pool_id", "")
    if not pool_id:
        return ""
    
    section_count = meta.get("section_count", "0")
    snat = meta.get("snat", "")
    result = "nat address-group " + pool_id + " " + section_count + "\n"
    result += "section 0 " + snat + " " + snat + "\n"
    
    return result

def render_policy(intent, meta):
    """渲染安全策略模板"""
    result = "security-policy\n"
    result += " rule name " + meta.get("policy_name", "") + "\n"
    

    if not meta.get("is_reused"):
        # 源区域
        for zone in meta.get("sourceZones", []):
            result += "  source-zone " + zone + "\n"
        
        # 目标区域
        for zone in meta.get("destinationZones", []):
            result += "  destination-zone " + zone + "\n"
    
    # 源地址（对象模式 vs 内联模式）
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "  source-address address-set " + item + "\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "  source-address " + item.ip + " mask 255.255.255.255\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "  source-address range " + item.first + " " + item.last + "\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "  source-address " + item.ip + " mask 255.255.255.255\n"
                elif item.type == "RANGE":
                    result += "  source-address range " + item.first + " " + item.last + "\n"
                else:
                    result += "  source-address " + item.ip + " mask " + item.mask.dotted + "\n"
            elif hasattr(item, "cidr"):
                parts = item.cidr.split("/")
                if len(parts) == 2:
                    result += "  source-address " + parts[0] + " mask " + item.mask.dotted + "\n"
            else:
                result += "  source-address " + item.ip + " mask " + item.mask.dotted + "\n"
    
    # 目标地址（对象模式 vs 内联模式）
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "  destination-address address-set " + item + "\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "  destination-address " + item.ip + " mask 255.255.255.255\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "  destination-address range " + item.first + " " + item.last + "\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "  destination-address " + item.ip + " mask 255.255.255.255\n"
                elif item.type == "RANGE":
                    result += "  destination-address range " + item.first + " " + item.last + "\n"
                else:
                    result += "  destination-address " + item.ip + " mask " + item.mask.dotted + "\n"
            elif hasattr(item, "cidr"):
                parts = item.cidr.split("/")
                if len(parts) == 2:
                    result += "  destination-address " + parts[0] + " mask " + item.mask.dotted + "\n"
            else:
                result += "  destination-address " + item.ip + " mask " + item.mask.dotted + "\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "  service " + item + "\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "  service any\n"
        else:
            for item in intent.service.EachDetailed():
                protocol = item.protocol
                result += "  service protocol " + protocol.lower
                
                if protocol.Equal("TCP") or protocol.Equal("UDP"):
                    if hasattr(item, "src_port") and not item.src_port.isFull:
                        if item.src_port.count == 1:
                            result += " source-port " + item.src_port.compact
                        else:
                            result += " source-port " + item.src_port.first + " to " + item.src_port.last
                    if hasattr(item, "dst_port") and not item.dst_port.isFull:
                        if item.dst_port.count == 1:
                            result += " destination-port " + item.dst_port.compact
                        else:
                            result += " destination-port " + item.dst_port.first + " to " + item.dst_port.last
                elif protocol.Equal("ICMP"):
                    if hasattr(item, "hasType") and item.hasType:
                        result += " icmp-type " + str(item.type)
                        if hasattr(item, "hasCode") and item.hasCode:
                            result += " " + str(item.code)
                
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
    result = "nat-policy\n"
    result += " rule name " + meta.get("nat_name", "") + "\n"
    
    if meta.get("description"):
        result += "  description " + meta["description"] + "\n"
    
    # 源区域
    for zone in meta.get("sourceZones", []):
        result += "  source-zone " + zone + "\n"
    
    # 目标区域
    for zone in meta.get("destinationZones", []):
        result += "  destination-zone " + zone + "\n"
    
    # 源地址（对象模式 vs 内联模式）
    if meta.get("has_source_objects"):
        for item in meta.get("src_objects", []):
            result += "  source-address address-set " + item + "\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "  source-address " + item.ip + " mask 255.255.255.255\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "  source-address range " + item.first + " " + item.last + "\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "  source-address " + item.ip + " mask 255.255.255.255\n"
                elif item.type == "RANGE":
                    result += "  source-address range " + item.first + " " + item.last + "\n"
                else:
                    result += "  source-address " + item.ip + " mask " + item.mask.dotted + "\n"
            elif hasattr(item, "cidr"):
                parts = item.cidr.split("/")
                if len(parts) == 2:
                    result += "  source-address " + parts[0] + " mask " + item.mask.dotted + "\n"
            else:
                result += "  source-address " + item.ip + " mask " + item.mask.dotted + "\n"
    
    # 目标地址（对象模式 vs 内联模式）
    if meta.get("has_destination_objects"):
        for item in meta.get("dst_objects", []):
            result += "  destination-address address-set " + item + "\n"
    else:
        # 内联模式：使用布尔属性判断类型
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            if hasattr(item, "isHost") and item.isHost:
                result += "  destination-address " + item.ip + " mask 255.255.255.255\n"
            elif hasattr(item, "isRange") and item.isRange:
                result += "  destination-address range " + item.first + " " + item.last + "\n"
            elif hasattr(item, "type"):
                if item.type == "HOST":
                    result += "  destination-address " + item.ip + " mask 255.255.255.255\n"
                elif item.type == "RANGE":
                    result += "  destination-address range " + item.first + " " + item.last + "\n"
                else:
                    result += "  destination-address " + item.ip + " mask " + item.mask.dotted + "\n"
            elif hasattr(item, "cidr"):
                parts = item.cidr.split("/")
                if len(parts) == 2:
                    result += "  destination-address " + parts[0] + " mask " + item.mask.dotted + "\n"
            else:
                result += "  destination-address " + item.ip + " mask " + item.mask.dotted + "\n"
    
    # 服务（对象模式 vs 内联模式）
    if meta.get("has_service_objects"):
        for item in meta.get("service_objects", []):
            result += "  service " + item + "\n"
    else:
        # IP协议特殊处理
        if meta.get("is_ip_protocol", False):
            result += "  service any\n"
        else:
            for item in intent.service.EachDetailed():
                protocol = item.protocol
                result += "  service protocol " + protocol.lower
                
                if protocol.Equal("TCP") or protocol.Equal("UDP"):
                    if hasattr(item, "src_port") and not item.src_port.isFull:
                        if item.src_port.count == 1:
                            result += " source-port " + item.src_port.compact
                        else:
                            result += " source-port " + item.src_port.first + " to " + item.src_port.last
                    if hasattr(item, "dst_port") and not item.dst_port.isFull:
                        if item.dst_port.count == 1:
                            result += " destination-port " + item.dst_port.compact
                        else:
                            result += " destination-port " + item.dst_port.first + " to " + item.dst_port.last
                elif protocol.Equal("ICMP"):
                    if hasattr(item, "hasType") and item.hasType:
                        result += " icmp-type " + str(item.type)
                        if hasattr(item, "hasCode") and item.hasCode:
                            result += " " + str(item.code)
                
                result += "\n"
    
    # NAT动作
    nat_type = meta.get("nat_type", "")
    if nat_type == "DNAT":
        if meta.get("mip_name"):
            result += "  action destination-nat address-group " + meta["mip_name"]
        else:
            result += "  action destination-nat address " + intent.real_ip
        if intent.real_port:
            result += " " + intent.real_port
        result += "\n"
    else:
        if meta.get("has_pool_id"):
            result += "  action source-nat address-group " + meta.get("pool_id", "") + "\n"
        else:
            result += "  action source-nat easy-ip\n"
    
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
    "MIP": render_mip,
    "SnatPool": render_snat_pool,
    "Policy": render_policy,
    "NatPolicy": render_nat_policy,
}

