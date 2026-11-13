# /etc/nginx/allowlists/admin.geo
# Networks allowed to reach admin locations, one "<cidr> 1;" per line (IPv4 and IPv6).
# Owned root:root 0644, reviewed like any access right. Never add 0.0.0.0/0, ::/0
# or a whole cloud-provider range. Behind a load balancer, real_ip must be configured first.
# An empty list denies everyone: admin locations return 404.

127.0.0.1/32    1;
::1/128         1;
# 192.0.2.0/28    1;    # ADAPT: admin VPN egress
# 2001:db8:10::/64 1;   # ADAPT: admin VPN egress (IPv6)
