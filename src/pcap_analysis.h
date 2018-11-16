#ifndef PCAP_ANALYSIS_H_
#define PCAP_ANALYSIS_H_

    #include <pcap.h>

    #define LINKTYPE_NULL       0x00
    #define LINKTYPE_ETHERNET   0x01
    #define LINKTYPE_LINUX_SLL  0x71

    // LINUX COOKED SLL header
    // https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    struct linuxhdr {
        uint16_t packet_type;
        uint16_t arphrd_type;
        uint16_t ll_adr_length;
        u_int64_t ll_adr;
        uint16_t protocol_type;
    };

    /**
     * @brief Per packet analysis
     * 
     * @param user_argument argument passed in to the callback
     * @param h packet meta with timestamp
     * @param bytes pointer to the actual packet data
     */
    void pcap_analysis(u_char* user_argument, const struct pcap_pkthdr* h, const u_char* bytes);

#endif // PCAP_ANALYSIS_H_