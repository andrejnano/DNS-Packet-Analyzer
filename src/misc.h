#ifndef MISC_H_
#define MISC_H_

    #include "dns-header.h"
    #include <inttypes.h>

    // terminal output ANSI colors and formatting
    #define RED         "\x1b[31m"
    #define GREEN       "\x1b[32m"
    #define YELLOW      "\x1b[33m"
    #define BLUE        "\x1b[34m"
    #define MAGENTA     "\x1b[35m"
    #define CYAN        "\x1b[36m"
    #define BOLD        "\033[1m"
    #define ITALIC      "\033[3m"
    #define UNDERLINE   "\033[4m"
    #define BLINK       "\033[5m"
    #define BG_BLUE     "\033[44m"
    #define RESET       "\033[0m"
    
    // these are all debug functions, used by me during developement, final version of this program doesn't use them
    void print_filler();
    void print_offset(int32_t packet_offset_size);
    void debug_print_packet_start(const struct pcap_pkthdr* h);
    void debug_print_packet_end();

    void debug_print_eth(const u_short eth_type, struct ether_header * eth_hdr, int32_t packet_offset_size);
    void debug_print_ip(const u_short eth_type, const struct ip* ip_hdr, int32_t packet_offset_size);
    void debug_print_udp(const struct udphdr* udp_hdr, int32_t packet_offset_size);
    void debug_print_tcp(const struct tcphdr* tcp_hdr, int32_t packet_offset_size);

    void debug_print_dns(int32_t packet_offset_size, dnshdr * dns_hdr);

#endif // MISC_H_ 