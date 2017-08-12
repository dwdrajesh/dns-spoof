# dns-spoof

Uses raw socket to intercept DNS query messages.
Parses Ethernet, IP, UDP and DNS header and sends spoof reply back to the sender.
Needs root access to obtain raw packets on Linux.

Compile: make
Run: sudo ./raw_socket_parse

Spoof reply currently hardcoded.

Raw packet ---> Ethernet header ---> IP Header ---> UDP header ---> Port 53 for DNS messages
DNS Header ---> Query name of the form: www.google.com is sent as 3www6google3com0

