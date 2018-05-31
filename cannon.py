from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr,IPAddr6,EthAddr
import re

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url

        self.target_ips = dict()
        self.seq = 0
        self.ack = 0
        self.len = 0
        
    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        # Check DNS query against domain name, and record IP address 
        # ethernet - IP - UDP - DNS 
        udp_packet = ip_packet.find('udp')
        if udp_packet is not None:
            self.handle_dns(udp_packet.find('dns'))

        # If we have ip address match
        tcp_packet = ip_packet.find('tcp')
        if tcp_packet is not None and str(ip_packet.srcip) in self.target_ips:
            self.handle_tcp(tcp_packet)

    	# Must return an ip packet or None
    	return ip_packet

    # Input: an instance of dns packet
    # Output: Boolean, True if successfully track target IP, False otherwise
    def handle_dns(self, dns_packet): 
        if dns_packet is not None: 
            if dns_packet.qr == True: 
                if self.target_domain_re.search(dns_packet.questions[0].name) != None: 
                    for answer in dns_packet.answers:
                        if len(answer.rddata) == 4:
                            self.target_ips[str(IPAddr(answer.rddata))] = True
        return False

    # Input: an instance of tcp packet
    # Output: an instance of tcp packet (modified or unmodified)
    def handle_tcp(self, tcp_packet):
        # this is a tcp handshake message
        if len(tcp_packet.payload) == 0:
            # print tcp_packet
            return tcp_packet
        # otherwise, we might need to modify payload
        else: 
            return self.handle_http(tcp_packet.payload)

    # Input: http response [hdr, body]
    # Output: http response [hdr, body]
    def handle_http(self, http_packet):

        return http_packet


