#ifndef PARSE_DNS_H_
#define PARSE_DNS_H_

    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/if_ether.h> 
    #include <iostream>
    #include <iomanip>

    #include "pcap_analysis.h"
    #include "misc.h"

    /**
     *  @brief Parse DNS frame of the packet
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     */
    void parse_dns(const u_char* bytes, int32_t packet_offset_size);

    /**
     *  @brief Parse a Question in the Questions section on the DNS frame of the packet
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     */
    size_t parse_dns_question(const u_char* bytes, int32_t packet_offset_size);

    /**
     *  @brief Parse an Answer in the Answers section in the DNS frame of the packet
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     */
    int32_t parse_dns_answer(const u_char* bytes, int32_t packet_offset_size);
    
    /**
     *  @brief Parse the label/ptr name field in the DNS frame
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     *  @param name string to which the parsed content will be stored
     *  @param is_pointer_reference flag describing the context in which the name parsing is run
     *  @param depth of the recursive pointer call
     * 
     *  @return updated packet_offset_size
     */
    int32_t parse_dns_name_field(const u_char* bytes, 
                                int32_t packet_offset_size, 
                                std::string &name, 
                                bool is_pointer_reference,
                                uint8_t depth = 0);

    /**
     *  @brief Parse one or more <character-string>s and save them into a string
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     *  @param name string to which the parsed content will be stored
     * 
     *  @return updated packet_offset_size
     */
    size_t parse_dns_string(const u_char* bytes, int32_t packet_offset_size, std::string &name);

    /**
     *  @brief Parse the Record Data field in the DNS frame 
     * 
     *  @param bytes pointer to the packet
     *  @param packet_offset_size current offset in the packet
     *  @param type DNS RR type 
     *  
     *  @return parsed RDATA
     */
    std::string parse_dns_answer_rdata(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length, uint16_t type);
    
    /**
     *  @brief Converts integer DNS type to a readable string format
     * 
     *  @param type DNS RR type 
     *  
     *  @return converted string type
     */
    std::string dns_type_to_string(uint16_t type);

    std::string parse_dns_answer_rdata_soa(const u_char* bytes, int32_t packet_offset_size);
    std::string parse_dns_answer_rdata_mx(const u_char* bytes, int32_t packet_offset_size);

    // DNSSEC 
    std::string parse_dns_answer_rdata_rrsig(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length);
    std::string parse_dns_answer_rdata_dnskey(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length);
    std::string parse_dns_answer_rdata_nsec(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length);
    std::string parse_dns_answer_rdata_ds(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length);
    
#endif // PARSE_DNS_H_