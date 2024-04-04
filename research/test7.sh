#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_test7_kern.c -o xdp_test7_kern.o
sudo ip link set test xdpgeneric off
sudo ip link set test xdpgeneric obj xdp_test7_kern.o sec xdp_icmp_echo
