#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_test2_kern.c -o xdp_test2_kern.o
sudo ip link set test xdpgeneric off
sudo ip link set test xdpgeneric obj xdp_test2_kern.o sec xdp_icmp_echo
