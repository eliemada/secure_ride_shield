sudo ifconfig eth0 10.10.0.5/24 up # Set the IP address of the VM3
sudo iptables -F # Flush the iptables
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -s 10.10.0.15 -j ACCEPT
sudo iptables -A INPUT -s 10.10.0.1 -j ACCEPT
sudo iptables -A INPUT -s 10.10.0.50 -j ACCEPT
sudo iptables -P INPUT DROP