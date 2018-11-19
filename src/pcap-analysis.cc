#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

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

/**
 * @brief Layer by layer analysis of packets from either ``static file`` or a live interface
 * 
 * @description Analysis starts by parsing L2 layer, accepting only ethernet or Linux SSL frames.
 * Then, depending on the underlying network protocol type, parsing of the L3 layer begins.
 * Both IPv4 and IPv6 are accepted. Next, transport protocols on the L4 layer are parsed (TCP or UDP).
 * After the parsing completes successfuly, DNS parsing in a separate functions is initiated, 
 * taking the current packet offset and pointer to the packet data
 * 
 * @param custom argument passed in the callback, in this case a link layer type should be used
 * @param h pcap header containing the current packet's length, timestamp, etc.
 * @param bytes pointer to the actual data of the current packet
 */
void pcap_analysis(u_char* user_argument, const struct pcap_pkthdr* h, const u_char* bytes)
{
    // size of the whole packet in bytes
    const int32_t full_packet_size = static_cast<int32_t>(h->len);
    // dynamic size of the offset inside the current packet
    int32_t packet_offset_size = 0;
    
    // link protocol type
    uint16_t L2_PROTOCOL = (*( (uint16_t*) user_argument ));
    // network protocol type
    uint16_t L3_PROTOCOL;
    // transport protocol type
    uint16_t L4_PROTOCOL;


    /*-----------------------------------------------------------------------*/
    /*                               L2                                      */
    /*-----------------------------------------------------------------------*/

    if (L2_PROTOCOL == LINKTYPE_ETHERNET)
    {
        struct ether_header * eth_hdr = (struct ether_header*) bytes;
        L3_PROTOCOL = ntohs(eth_hdr->ether_type);
        packet_offset_size += sizeof(*eth_hdr);
    }
    else if (L2_PROTOCOL == LINKTYPE_LINUX_SLL) //  LINUX COOKED CAPTURE FRAME
    {
        struct linuxhdr * linux_hdr = (struct linuxhdr*) bytes;
        L3_PROTOCOL = ntohs(linux_hdr->protocol_type);
        packet_offset_size += sizeof(*linux_hdr);
    }
    else { return; } // Unsupported L2 type -> skip


    /*-----------------------------------------------------------------------*/
    /*                               L3                                      */
    /*-----------------------------------------------------------------------*/

    if (L3_PROTOCOL == ETHERTYPE_IP)
    {
        const struct ip* ip4_hdr = (struct ip*) (bytes + packet_offset_size);
        packet_offset_size += ip4_hdr->ip_hl * 4;
        L4_PROTOCOL = static_cast<uint16_t>(ip4_hdr->ip_p);
    }
    else if (L3_PROTOCOL == ETHERTYPE_IPV6)
    {
        const struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) (bytes + packet_offset_size);
        packet_offset_size += sizeof(*ip6_hdr);
        L4_PROTOCOL = static_cast<uint16_t>(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    }
    else { return; }  // Unsupported L3 type -> skip
    

    /*-----------------------------------------------------------------------*/
    /*                               L4                                      */
    /*-----------------------------------------------------------------------*/

    if (L4_PROTOCOL == IPPROTO_UDP)
    {   
        const struct udphdr* udp_hdr = (struct udphdr *) (bytes + packet_offset_size);
        packet_offset_size += sizeof(*udp_hdr);
    }
    else if (L4_PROTOCOL == IPPROTO_TCP)
    {
        const struct tcphdr* tcp_hdr = (struct tcphdr *) (bytes + packet_offset_size);
        
        // skip tcp header size
        #if (defined(__FAVOR_BSD))
        packet_offset_size += tcp_hdr->th_off * 4;
        #else
        packet_offset_size += tcp_hdr->doff * 4;
        #endif
        
        // DNS in TCP has 2 octets at the beginning specifying the DNS msg length
        uint16_t* dns_message_length = (uint16_t*) (bytes + packet_offset_size);
        packet_offset_size += sizeof(dns_message_length);

        // if the DNS msg length is greater than TCP payload (without the 2 octets of dns length)
        // this signals that the DNS msg is fragmented into multiple packets.
        // TCP fragmentation is not supported, therefore skip this packet
        if ( (full_packet_size - packet_offset_size) < ntohs(*dns_message_length))
        {
            return;
        }
        
    }
    else { return; } // Unsupported L4 type -> skip


    /*-----------------------------------------------------------------------*/
    /*                               L7                                      */
    /*-----------------------------------------------------------------------*/

    parse_dns(bytes, packet_offset_size);

}
