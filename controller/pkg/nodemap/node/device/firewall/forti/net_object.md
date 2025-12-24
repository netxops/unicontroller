fortigate的nat和其他防火墙不太一样，vip包含了外部IP（extip）和内部ip（mappedip），pool与其他基本一致。
config firewall vip
edit "${VipName}"
	set extip ${ExtIp}
	set mappedip ${MappedIp}
	set extintf "${ExtIntf}"
	set portforward enable
	set extport ${ExtPort}
	set mappedport ${MappedPort}
next
end

config firewall vip
edit "${VipName}"
    set extip ${ExtIp}
    set mappedip ${MappedIp}
    set extintf "${ExtIntf}"
    set portforward disable
next
end


config firewall ippool
edit "${PoolName}"
    set type overload
    set startip ${StartIp}
    set endip ${EndIp}
next
end