#!/bin/bash
#observer -name mqr -d capture0 -mP 13306 -rh 10.55.2.51 -rP 16379 -rp test123
nohup observer -name mqr -d capture0 -mP 13306 -rh 10.55.2.51 -rP 16379 -rp test123 > observer.log 2>&1 &
