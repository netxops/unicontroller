			set\ssecurity\snat\s(?P<direct>\S+)\spool\s(?P<name>\S+)\s
			(
				(
					address\s(?P<address>\d+\.\d+\.\d+\.\d+)(/(?P<addr_prefix>\d+))?\s*
					(to\s(?P<address2>\d+\.\d+\.\d+\.\d+)(/(?P<addr2_prefix>\d+))?)?
				) |
				((address\s)?port\s(range\s)?to\s(?P<port_to>\d+)) |
				((address\s)?port\s(range\s)?(?P<port_from>\d+))
			)

其中direct有source和destination