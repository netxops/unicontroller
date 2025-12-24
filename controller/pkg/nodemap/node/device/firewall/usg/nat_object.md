
// parseNatAddressGroups parses nat address-group configurations
// Format: nat address-group 1 0
//
//	section 0 1.1.1.1 1.1.1.22

destination-nat address-group
// Format: destination-nat address-group group_name_xxx 0
//
//	section 6.6.6.6 6.6.6.10



inside-ipv4-pool\s+(?P<pool_id>\d+)\s*\n
            (?P<sections>(?:\s+section\s+\d+\s+[\d\.]+\s+[\d\.]+\s*\n?)*)
global-pool\s+(?P<pool_id>\d+)\s*\n
            (?P<sections>(?:\s+section\s+\d+\s+[\d\.]+\s+[\d\.]+\s*\n?)*)