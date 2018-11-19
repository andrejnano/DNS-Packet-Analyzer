/**
 *  @file       debugs.cc
 *  @author     Andrej Nano (xnanoa00)
 *  @date       2018-11-19
 *  @version    1.0
 * 
 *  @brief  DNS protocol information export using the Syslog protocol | ISA 2018/19 (Export DNS informací pomocí protokolu Syslog)
 *  
 *  @section Description
 *  This program creates statistics about DNS communication and exports them to a syslog server.
 */

/*****************************************************************************
 *                                                                           
 * 
 *          THIS SOURCE FILE INCLUDES DEVELOPEMENT DEBUG HELPERS
 *          
 *          for simplicity and building without problems,
 *          I commented out all the functions.
 *
 */ 
/*****************************************************************************/

/*
#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <time.h>

#include "misc.h"
#include "dns-header.h"


void print_filler() {
    std::cout << "|" << std::setfill(' ') << std::setw(48);
}

void print_offset(int32_t packet_offset_size) {
    std::cout << "|\t" << BLINK << ITALIC << BG_BLUE << "@OFFSET:" << BOLD << " +" << std::setfill('0') << std::setw(3) << packet_offset_size << "B" << RESET;
}

void debug_print_packet_start(const struct pcap_pkthdr* h) {

    struct tm  ts;
    char timestring[80];

    ts = *localtime(&h->ts.tv_sec);
    strftime(timestring, sizeof(timestring), "%a %Y-%m-%d %H:%M:%S %Z", &ts);

    std::cout << "\n+" << std::setfill('-') << std::setw(120) << "+" << RESET << std::endl;
    std::cout << "|" << ITALIC << " 📦  parsing a packet... ➤ " << RESET << " [ 🕔 : " << BOLD << timestring << RESET << ", length: " << BOLD << h->len << RESET << " bytes}" << RESET << std::endl;
    std::cout << "+" << std::setfill('-') << std::setw(120) << "+" << RESET << std::endl;
    std::cout << "|" << std::endl;
}

void debug_print_packet_end() {
    std::cout << "|" << std::endl;
    std::cout << "+" << std::setfill('-') << std::setw(120) << "+" << RESET << std::endl;
}

void debug_print_eth(const u_short eth_type, struct ether_header * eth_hdr, int32_t packet_offset_size) {
    print_offset(packet_offset_size);
    std::cout << " | " << RESET << "(L2) - 🔌  <";
    std::cout << GREEN << BOLD << "ETH" << RESET;
    
    std::cout << "> \t[src mac: " << BOLD << GREEN << std::setfill(' ') << std::setw(18) << ether_ntoa((const struct ether_addr *)&eth_hdr->ether_shost) << RESET;
    std::cout << ", dst mac: " << BOLD << GREEN << std::setfill(' ') << std::setw(18) << ether_ntoa((const struct ether_addr *)&eth_hdr->ether_dhost) << RESET;
    std::cout << "] [type: " << BOLD << "0x" << std::setfill('0') << std::setw(4) << std::hex << eth_type << std::dec << RESET << "] " << std::endl;
}

void debug_print_ip(const u_short eth_type, const struct ip* ip_hdr, int32_t packet_offset_size) {
    print_offset(packet_offset_size);
    std::cout << " | " << RESET << "(L3) - 💻  <";
    if (eth_type == ETHERTYPE_IP) {
        std::cout << BLUE << BOLD << "IPv4" << RESET;
    }
    else if (eth_type == ETHERTYPE_IPV6) {
        std::cout << BLUE << BOLD << "IPv6" << RESET;
    }
    
    std::cout << "> \t[src host: " << BOLD << BLUE << std::setfill(' ') << std::setw(17) << inet_ntoa(ip_hdr->ip_src) << RESET;
    std::cout << ", dst host: " << BOLD << BLUE << std::setfill(' ') << std::setw(17) << inet_ntoa(ip_hdr->ip_dst) << RESET << "]" << std::endl;

}

void debug_print_udp(const struct udphdr* udp_hdr, int32_t packet_offset_size) {
    print_offset(packet_offset_size);
    std::cout << " | " << RESET << "(L4) - 🚚  <";
    std::cout << RED << BOLD << "UDP" << RESET;
    
    std::cout << "> \t[src port: " << BOLD << RED << std::setfill(' ') << std::setw(17) << ntohs(udp_hdr->uh_sport) << RESET;
    std::cout << ", dst port: " << BOLD << RED << std::setfill(' ') << std::setw(17) << ntohs(udp_hdr->uh_dport) << RESET << "]" << std::endl;
}

void debug_print_tcp(const struct tcphdr* tcp_hdr, int32_t packet_offset_size) {
    print_offset(packet_offset_size);
    std::cout << " | " << RESET << "(L4) - 🚚  <";
    std::cout << YELLOW << BOLD << "TCP" << RESET;
    
    std::cout << "> \t[src port: " << BOLD << YELLOW << std::setfill(' ') << std::setw(17) << ntohs(tcp_hdr->th_sport) << RESET;
    std::cout << ", dst port: " << BOLD << YELLOW << std::setfill(' ') << std::setw(17) << ntohs(tcp_hdr->th_dport) << RESET;
    std::cout << "] [seq: " <<  ntohs(tcp_hdr->th_seq) << "]" << std::endl;
}

void debug_print_dns(int32_t packet_offset_size, dnshdr * dns_hdr) {
    print_offset(packet_offset_size);
    std::cout << " | " << RESET << "(L7) - 🔗  <";
    std::cout << MAGENTA << BOLD << "D" << CYAN << "N" << RED << "S" << RESET;
    
    std::cout << "> \t[id: " << MAGENTA << BOLD << "0x" << std::hex << ntohs(dns_hdr->id) << std::dec << RESET << "] -> ";
    if (dns_hdr->qr == 0) { std::cout << YELLOW << BOLD << "QUERY"; }
    else if (dns_hdr->qr == 1) { std::cout << CYAN << BOLD << "RESPONSE"; }
    else { std::cout << " - "; }
    
    std::cout << RESET << std::endl;
    std::cout << "|" << std::setfill(' ') << std::setw(48) << "[";
    std::cout << "qr: " << MAGENTA << BOLD << dns_hdr->qr << RESET << ", ";
	std::cout << "opcode: " << MAGENTA << BOLD << dns_hdr->opcode << RESET << ", ";
	std::cout << "aa: " << MAGENTA << BOLD << dns_hdr->aa << RESET << ", ";
	std::cout << "tc: " << MAGENTA << BOLD << dns_hdr->tc << RESET << ", ";
	std::cout << "rd " << MAGENTA << BOLD << dns_hdr->rd  << RESET << ", ";
	std::cout << "ra: " << MAGENTA << BOLD << dns_hdr->ra << RESET << ", ";
	std::cout << "zero: " << MAGENTA << BOLD << dns_hdr->zero << RESET << ", ";
	std::cout << "rcode: " << MAGENTA << BOLD << dns_hdr->rcode << RESET << "]" << std::endl;

    std::cout << "|" << std::setfill(' ') << std::setw(48) << "[";
    std::cout << "qcount:  " << MAGENTA << BOLD << ntohs(dns_hdr->qcount) << RESET << "] ";
    std::cout << "[ancount: " << MAGENTA << BOLD << ntohs(dns_hdr->ancount) << RESET << "] ";
    std::cout << "[nscount: " << MAGENTA << BOLD << ntohs(dns_hdr->nscount) << RESET << "] ";
    std::cout << "[adcount: " << MAGENTA << BOLD << ntohs(dns_hdr->adcount) << RESET << "]" << std::endl;
}
*/

