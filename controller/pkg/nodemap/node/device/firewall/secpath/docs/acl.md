Configuring an IPv4 basic ACL
1.     Enter system view.

system-view
2.     Create an IPv4 basic ACL and enter its view. Choose one option as needed:
¡     Create an IPv4 basic ACL by specifying an ACL number.
acl number acl-number [ name acl-name ] [ match-order { auto | config } ]
¡     Create an IPv4 basic ACL by specifying the basic keyword.
acl basic { acl-number | name acl-name } [ match-order { auto | config } ]

3.     (Optional.) Configure a description for the IPv4 basic ACL.
description text
By default, an IPv4 basic ACL does not have a description.

4.     (Optional.) Enable rule ID preemption.
rule insert-only enable
By default, rule ID preemption is disabled.

5.     (Optional.) Set the rule numbering step.
step step-value
By default, the rule numbering step is 5 and the start rule ID is 0.

6.     Create or edit a rule.
rule [ rule-id ] { deny | permit } [ counting | fragment | logging | source { object-group address-group-name | source-address source-wildcard | any } | time-range time-range-name | vpn-instance vpn-instance-name ] *
The logging keyword takes effect only when the module (for example, packet filtering) that uses the ACL supports logging.

7.     (Optional.) Add or edit a rule comment.
rule rule-id comment text
By default, no rule comment is configured.

Configuring an IPv6 basic ACL
1.     Enter system view.

system-view
2.     Create an IPv6 basic ACL view and enter its view. Choose one option as needed:
¡     Create an IPv6 basic ACL by specifying an ACL number.
acl ipv6 number acl-number [ name acl-name ] [ match-order { auto | config } ]
¡     Create an IPv6 basic ACL by specifying the basic keyword.
acl ipv6 basic { acl-number | name acl-name } [ match-order { auto | config } ]
3.     (Optional.) Configure a description for the IPv6 basic ACL.
description text

By default, an IPv6 basic ACL does not have a description.
4.     (Optional.) Enable rule ID preemption.

rule insert-only enable
By default, rule ID preemption is disabled.

5.     (Optional.) Set the rule numbering step.
step step-value
By default, the rule numbering step is 5 and the start rule ID is 0.

6.     Create or edit a rule.
rule [ rule-id ] { deny | permit } [ counting | fragment | logging | routing [ type routing-type ] | source { object-group address-group-name | source-address source-prefix | source-address/source-prefix | any } | time-range time-range-name | vpn-instance vpn-instance-name ] *

The logging keyword takes effect only when the module (for example, packet filtering) that uses the ACL supports logging.

7.     (Optional.) Add or edit a rule comment.
rule rule-id comment text
By default, no rule comment is configured.




Configuring an IPv4 advanced ACL
1.     Enter system view.
system-view

2.     Create an IPv4 advanced ACL and enter its view. Choose one option as needed:
¡     Create a numbered IPv4 advanced ACL by specifying an ACL number.
acl number acl-number [ name acl-name ] [ match-order { auto | config } ]
¡     Create an IPv4 advanced ACL by specifying the advanced keyword.
acl advanced { acl-number | name acl-name } [ match-order { auto | config } ]

3.     (Optional.) Configure a description for the IPv4 advanced ACL.
description text
By default, an IPv4 advanced ACL does not have a description.

4.     (Optional.) Enable rule ID preemption.
rule insert-only enable
By default, rule ID preemption is disabled.

5.     (Optional.) Set the rule numbering step.
step step-value
By default, the rule numbering step is 5 and the start rule ID is 0.

6.     Creaete or edit a rule.
rule [ rule-id ] { deny | permit } protocol [ { { ack ack-value | fin fin-value | psh psh-value | rst rst-value | syn syn-value | urg urg-value } * | established } | counting | destination { object-group address-group-name | dest-address dest-wildcard | any } | destination-port { object-group port-group-name | operator port1 [ port2 ] } | { dscp dscp | { precedence precedence | tos tos } * } | fragment | icmp-type { icmp-type [ icmp-code ] | icmp-message } | logging | source { object-group address-group-name | source-address source-wildcard | any } | source-port { object-group port-group-name | operator port1 [ port2 ] } | time-range time-range-name | vpn-instance vpn-instance-name ] *

The logging keyword takes effect only when the module (for example, packet filtering) that uses the ACL supports logging.

7.     (Optional.) Add or edit a rule comment.
rule rule-id comment text
By default, no rule comment is configured.


Configuring an IPv6 advanced ACL
1.     Enter system view.
system-view

2.     Create an IPv6 advanced ACL and enter its view. Choose one option as needed:
¡     Create a numbered IPv6 advanced ACL by specifying an ACL number.

acl ipv6 number acl-number [ name acl-name ] [ match-order { auto | config } ]
¡     Create an IPv6 advanced ACL by specifying the advanced keyword.

acl ipv6 advanced { acl-number | name acl-name } [ match-order { auto | config } ]
3.     (Optional.) Configure a description for the IPv6 advanced ACL.

description text
By default, an IPv6 advanced ACL does not have a description.

4.     (Optional.) Enable rule ID preemption.

rule insert-only enable
By default, rule ID preemption is disabled.

5.     (Optional.) Set the rule numbering step.
step step-value
By default, the rule numbering step is 5 and the start rule ID is 0.

6.     Create or edit a rule.
rule [ rule-id ] { deny | permit } protocol [ { { ack ack-value | fin fin-value | psh psh-value | rst rst-value | syn syn-value | urg urg-value } * | established } | counting | destination { object-group address-group-name | dest-address dest-prefix | dest-address/dest-prefix | any } | destination-port { object-group port-group-name | operator port1 [ port2 ] } | dscp dscp | flow-label flow-label-value | fragment | icmp6-type { icmp6-type icmp6-code | icmp6-message } | logging | routing [ type routing-type ] | hop-by-hop [ type hop-type ] | source { object-group address-group-name | source-address source-prefix | source-address/source-prefix | any } | source-port { object-group port-group-name | operator port1 [ port2 ] } | time-range time-range-name | vpn-instance vpn-instance-name ] *

The logging keyword takes effect only when the module (for example, packet filtering) that uses the ACL supports logging.

7.     (Optional.) Add or edit a rule comment.
rule rule-id comment text
By default, no rule comment is configured.

