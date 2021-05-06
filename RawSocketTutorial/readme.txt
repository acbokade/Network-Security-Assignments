Create two virtual network interfaces:-
sudo ifconfig wlp0s20f3:0 192.168.1.21 up
sudo ifconfig wlp0s20f3:1 192.168.1.22 up


Task 1 - DNS Packet Parser
On first terminal:-
sudo make
sudo ./rawSocket wlp0s20f3:0

On second terminal:-
dig @192.168.1.22 rawsocket.tut



Task 2 - DNS client with RAW socket
On first terminal:-
sudo make
sudo ./rawSocket wlp0s20f3:0

On second terminal:-
g++ dnsClient.cpp -o dnsClient
./dnsClient
