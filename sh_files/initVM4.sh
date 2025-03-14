sudo ifconfig eth0 10.10.1.100/24 up # Set the IP address of the VM4
sudo iptables -F # Flush the iptables
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -s 10.10.1.10 -j ACCEPT
sudo iptables -P INPUT DROP


