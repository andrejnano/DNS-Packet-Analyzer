#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h> 
#include <iostream>
#include <iomanip>

#include "pcap_analysis.h"
#include "parse-dns.h"
#include "misc.h"

/*
    callback specifies a pcap_handler routine to be called with three arguments: 
    a u_char pointer which is passed in the user argument to pcap_loop() or pcap_dispatch(), 
    a const struct pcap_pkthdr pointer pointing to the packet time stamp and lengths, 
    and a const u_char pointer to the first caplen (as given in the struct 
    pcap_pkthdr a pointer to which is passed to the callback routine) bytes of data from the packet.
*/

void pcap_analysis(u_char* user_argument, const struct pcap_pkthdr* h, const u_char* bytes)
{
    // cursor to the current offset from the beginning of the whole packet
    size_t packet_offset_size = 0;
    
    // passed in link header type depending on the opened interface
    uint16_t* link_type_ptr = (uint16_t*) user_argument;
    uint16_t link_type = (*link_type_ptr);

    // network protocol type
    uint16_t net_type;

    std::cout << "link_type is " << link_type << std::endl;

    // L2 | ethernet frame
    if (link_type == LINKTYPE_ETHERNET)
    {
        struct ether_header * eth_hdr = (struct ether_header*) bytes;
        net_type = ntohs(eth_hdr->ether_type);
        packet_offset_size += sizeof(*eth_hdr);
    }
    // L2 | linux cooked frame
    else if (link_type == LINKTYPE_LINUX_SLL)
    {
        struct linuxhdr * linux_hdr = (struct linuxhdr*) bytes;
        net_type = ntohs(linux_hdr->protocol_type);
        packet_offset_size += sizeof(*linux_hdr);
    }
    // L2 | unsupported
    else
    {
        std::cout << "unsupported: " << link_type << std::endl;
        return;
    }

    // L3 | IPv4 
    if (net_type == ETHERTYPE_IP)
    {
        const struct ip* ip4_hdr = (struct ip*) (bytes + packet_offset_size);
        packet_offset_size += ip4_hdr->ip_hl * 4; // ipv4 header size

        // access the underlying transport protocol type from the IP header
        const u_char transport_protocol = ip4_hdr->ip_p;

        // L4 | UDP
        if (transport_protocol == IPPROTO_UDP)
        {   
            const struct udphdr* udp_hdr = (struct udphdr *) (bytes + packet_offset_size);
            packet_offset_size += sizeof(*udp_hdr); // udp header size
        }
        // L4 | TCP
        else if (transport_protocol == IPPROTO_TCP)
        {
            const struct tcphdr* tcp_hdr = (struct tcphdr *) (bytes + packet_offset_size);
            packet_offset_size += tcp_hdr->th_off * 4;  // tcp header size
            packet_offset_size += 2; // skip the 2 byte prefix (dns message length) in TCP/DNS message
        }
        // L4 | Other / Not supported
        else
        {
            return;
        }
    }
    // L3 | IPv6
    else if (net_type == ETHERTYPE_IPV6)
    {
        // cast the IPv6 header & increase the offset
        const struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) (bytes + packet_offset_size);
        packet_offset_size += sizeof(*ip6_hdr);
        
        // access the underlying transport protocol type from the IP header
        const u_char transport_protocol = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        
        // L4 | UDP
        if (transport_protocol == IPPROTO_UDP)
        { 
            const struct udphdr* udp_hdr = (struct udphdr *) (bytes + packet_offset_size);
            packet_offset_size += sizeof(*udp_hdr);
        }
        // L4 | TCP
        else if (transport_protocol == IPPROTO_TCP)
        {
            const struct tcphdr* tcp_hdr = (struct tcphdr *) (bytes + packet_offset_size);
            packet_offset_size += tcp_hdr->th_off * 4;  // tcp header size
            packet_offset_size += 2; // skip the 2 byte prefix (dns message length) in TCP/DNS message
        }
        // L4 | Other / Not Supported
        else { return; }
    }
    // L3 | Other / Not supported
    else { return; }

    // cast header, increase offset
    parse_dns(bytes, packet_offset_size);
}