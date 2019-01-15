#!/bin/bash

if [[ `id -u` != "0" ]]; then
	echo "You must run this as root/sudo"
	exit 1
fi

# Handle aliasing the IP address locally
echo "Adding alias on loopback for 127.0.0.2"
if [[ `uname -s` == "Darwin" ]]; then
	ifconfig lo0 alias 127.0.0.2 255.255.255.255
else
  if [[ `uname -s` == "linux" ]]; then
	ip address add 127.0.0.2/32 dev lo
  fi
fi
