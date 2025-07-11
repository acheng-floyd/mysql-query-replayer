#!/bin/bash
#applyer -name mqr -rh 127.0.0.1 -rP 16379 -rp test123 -mh 10.55.2.34 -mP 2883 -mu 'root@tenant_common#ob_cluster' -mp 'test123' -md saas_prod -ignore-limit
nohup applyer -name mqr -rh 127.0.0.1 -rP 16379 -rp test123 -mh 10.55.2.34 -mP 2883 -mu 'root@tenant_common#ob_cluster' -mp 'test123' -md saas_prod -ignore-limit > applyer.log 2>&1 &
