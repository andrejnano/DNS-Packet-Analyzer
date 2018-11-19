#include <netinet/in.h>
#include <sstream>
#include <iomanip>

#include "dns-header.h"
#include "parse-dns.h"
#include "statistics.h"
#include "base64.h"


// globally available statistics storage pointer
extern std::vector<StatisticEntry> *Statistics;

// globally available DNS frame offset in the current packet
// used by the pointers in the NAME fields, which reference by offset in the DNS frame
size_t DNS_PACKET_STARTING_OFFSET {0};

void parse_dns(const u_char* bytes, int32_t packet_offset_size)
{
    // init the starting offset
    DNS_PACKET_STARTING_OFFSET = static_cast<size_t>(packet_offset_size);

    // cast DNS header and increase offset
    dnshdr * dns_hdr = (dnshdr*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(dnshdr);

    // ignore/skip non-response DNS messages or corrupted messages
    if (dns_hdr->qr != 1) { return; }
    if (dns_hdr->opcode != 0) { return; }
    if (ntohs(dns_hdr->qcount) != 1) { return; }
    if (ntohs(dns_hdr->ancount) <= 0) { return; }
    
    // parse QUESTIONS section
    for (uint16_t qcounter = 0 ; qcounter < ntohs(dns_hdr->qcount) ; qcounter++)
    {
        packet_offset_size = parse_dns_question(bytes, packet_offset_size);
    }

    // parse ANSWERS section
    for (uint16_t ancounter = 0 ; ancounter < ntohs(dns_hdr->ancount) ; ancounter++)
    {
        packet_offset_size = parse_dns_answer(bytes, packet_offset_size);
        if (packet_offset_size == -1) { return; }
    }

    /* ignore both AUTHORITY & ADDITIONAL sections */
}


size_t parse_dns_question(const u_char* bytes, int32_t packet_offset_size) {
    
    // QNAME
    std::string qname;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, qname, false);

    // QTYPE
    uint16_t * qtype = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*qtype);

    // QCLASS
    uint16_t * qclass = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*qclass);

    return packet_offset_size;
}

int32_t parse_dns_answer(const u_char* bytes, int32_t packet_offset_size)
{
    bool is_accepted = true;

    // NAME
    std::string aname;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, aname, false);

    // TYPE
    uint16_t * atype = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*atype);
    std::string atype_str = dns_type_to_string(ntohs(*atype));

    if (atype_str == "")
    {
        is_accepted = false;
    }
    
    // CLASS
    uint16_t * aclass = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*aclass);

    // TTL
    int32_t * attl = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*attl);

    // RDLENGTH
    uint16_t * ardlength = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*ardlength);

    // corrupted packet, invalid rdlength
    if (ntohs(*ardlength) <= 0) 
    {
        return -1;
    }


    // RDATA
    std::string ardata = parse_dns_answer_rdata(bytes, packet_offset_size, ntohs(*ardlength), ntohs(*atype));
    packet_offset_size += ntohs(*ardlength);

    if (ardata == "")
    {
        is_accepted = false;
    }
    
    if (is_accepted)
    {
        // create new statistic entry
        log_answer(aname, atype_str, ardata);
    }

    return packet_offset_size;
}

std::string parse_dns_answer_rdata(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length, uint16_t type)
{
    // depending on the DNS message type, parse the RDATA field differently
    switch (type) {
        case DNS_QTYPE_A: {
            in_addr* ip_addr = (in_addr*) (bytes + packet_offset_size);
            return inet_ntoa(*ip_addr);
        }
        case DNS_QTYPE_NS: {
            std::string ns {""};
            parse_dns_name_field(bytes, packet_offset_size, ns, false);
            return ns;
        }
        case DNS_QTYPE_CNAME: {
            std::string cname {""};
            parse_dns_name_field(bytes, packet_offset_size, cname, false);
            return cname;
        }
        case DNS_QTYPE_SOA: {
            return parse_dns_answer_rdata_soa(bytes, packet_offset_size);
        }
        case DNS_QTYPE_PTR: {
            std::string ptr {""};
            parse_dns_name_field(bytes, packet_offset_size, ptr, false);
            return ptr;
        }
        case DNS_QTYPE_MX: {
            return parse_dns_answer_rdata_mx(bytes, packet_offset_size);
        }
        case DNS_QTYPE_AAAA: {
            in6_addr* ip_addr = (in6_addr*) (bytes + packet_offset_size);
            char outputbuf[45];
            return inet_ntop(AF_INET6, ip_addr, outputbuf, 45);
        }
        case DNS_QTYPE_TXT: {
            std::string txt {""};
            parse_dns_string(bytes, packet_offset_size, txt);
            return txt;
        }
        case DNS_QTYPE_RRSIG: {
            return parse_dns_answer_rdata_rrsig(bytes, packet_offset_size, rdata_length);
        }
        case DNS_QTYPE_NSEC: {
            return parse_dns_answer_rdata_nsec(bytes, packet_offset_size, rdata_length);
        }
        case DNS_QTYPE_DNSKEY: {
            return parse_dns_answer_rdata_dnskey(bytes, packet_offset_size, rdata_length);
        }
        case DNS_QTYPE_DS: {
            return parse_dns_answer_rdata_ds(bytes, packet_offset_size, rdata_length);
        }
        default: {
            return "";
        }
    }
    return "";
}

size_t parse_dns_string(const u_char* bytes, int32_t packet_offset_size, std::string &name)
{
    uint8_t *length_octet;
    int length;
    char * char_octet;
    std::string label;

    for(;;)
    {
        label = "";
        length_octet = (uint8_t*) (bytes + packet_offset_size);
        length = static_cast<int>(*length_octet);
        packet_offset_size += sizeof(*length_octet);

        // zero octet
        if (length == 0)
            break;
        
        // add each character to the label string
        for (int i = 0; i < length; i++) {
            char_octet = (char *) (bytes + packet_offset_size); 
            packet_offset_size += sizeof(*char_octet);
            label.append(char_octet, 0, sizeof(*char_octet));
        }

        name.append(label);
    }

    return packet_offset_size;
}


size_t parse_dns_name_field(const u_char* bytes, int32_t packet_offset_size, std::string &name, bool is_pointer_reference) {
    
    // reset the name if parsing a sequence of labels, otherwise dont
    if (!is_pointer_reference)
    {
        name = "";
    }

    uint8_t *length_octet;
    int length;
    char * char_octet;
    std::string label;

    // The compression scheme allows a domain name in a message to be represented as either:
    //  - a sequence of labels ending in a zero octet
    //  - a pointer
    //  - a sequence of labels ending with a pointer
    bool is_first_label = true;

    for(;;) {
        label = "";
        length_octet = (uint8_t*) (bytes + packet_offset_size);
        length = static_cast<int>(*length_octet);

        // compression test, pointer has the mask of 0xc0 (first 2 bits are set)
        if (*length_octet & static_cast<uint8_t>(0xc0))
        {
            uint16_t * pointer = (uint16_t*) (bytes + packet_offset_size);
            uint16_t pointer_offset = static_cast<uint16_t>(ntohs(*pointer)) & 0x3fff; // ignore first 2 bits

            // add the DNS frame's starting offset and the referenced label offset by the pointer
            size_t exact_offset = DNS_PACKET_STARTING_OFFSET + pointer_offset;

            // recursively get the name at the specified location
            parse_dns_name_field(bytes, exact_offset, name, true);

            packet_offset_size += sizeof(*pointer);
            return packet_offset_size;
        }

        packet_offset_size += sizeof(*length_octet);

        // zero octet
        if (length == 0)
            break;

        // don't add dot separator before the first label
        if (!is_first_label)
            label.append(".");

        // add each character to the label string
        for (int i = 0; i < length; i++)
        {
            char_octet = (char *) (bytes + packet_offset_size); 
            packet_offset_size += sizeof(*char_octet);
            label.append(char_octet, 0, sizeof(*char_octet));
        }
        
        name.append(label);
        
        is_first_label = false;
    }

    return packet_offset_size;
}


std::string dns_type_to_string(uint16_t type) {
    switch (type) {
        case DNS_QTYPE_A:       return "A";
        case DNS_QTYPE_NS:      return "NS";
        case DNS_QTYPE_CNAME:   return "CNAME";
        case DNS_QTYPE_SOA:     return "SOA";
        case DNS_QTYPE_PTR:     return "PTR";
        case DNS_QTYPE_MX:      return "MX";
        case DNS_QTYPE_AAAA:    return "AAAA";
        case DNS_QTYPE_TXT:     return "TXT";
        case DNS_QTYPE_RRSIG:   return "RRSIG";
        case DNS_QTYPE_DNSKEY:  return "DNSKEY";
        case DNS_QTYPE_NSEC:    return "NSEC";
        case DNS_QTYPE_DS:      return "DS";
        default:                return "";      // unsupported type
    }
}

std::string parse_dns_answer_rdata_soa(const u_char* bytes, int32_t packet_offset_size) {

    std::string mname;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, mname, false);

    std::string rname;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, rname, false);

    uint32_t * serial = (uint32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*serial);
    std::string serial_str = std::to_string( ntohl(*serial) );

    int32_t * refresh = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*refresh);
    std::string refresh_str = std::to_string( ntohl(*refresh) );

    int32_t * retry = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*retry);
    std::string retry_str = std::to_string( ntohl(*retry) );

    int32_t * expire = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*expire);
    std::string expire_str = std::to_string( ntohl(*expire) );

    uint32_t * minimum = (uint32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*minimum);
    std::string minimum_str = std::to_string( ntohl(*minimum) );

    std::ostringstream output;
    
    output  << "\""
            << mname << " "
            << rname << " "
            << serial_str << " "
            << refresh_str << " "
            << retry_str << " "
            << expire_str << " "
            << minimum_str << "\"";

    return output.str();
}

std::string parse_dns_answer_rdata_mx(const u_char* bytes, int32_t packet_offset_size)
{
    int16_t * preference = (int16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*preference);

    std::string preference_str = std::to_string( ntohl(*preference) );
    
    std::string exchange;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, exchange, false);

    std::ostringstream output;
    
    output  << "\""
            << preference_str << " "
            << exchange << "\"";

    return output.str();
}

std::string parse_dns_answer_rdata_rrsig(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length)
{
    size_t end_of_rdata = packet_offset_size + rdata_length;

    uint16_t* type_covered = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*type_covered);
    std::string type_covered_str = std::to_string( ntohs(*type_covered) );

    uint8_t* algorithm = (uint8_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*algorithm);
    std::string algorithm_str = std::to_string( *algorithm );

    uint8_t* labels = (uint8_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*labels);
    std::string labels_str = std::to_string( *labels );

    int32_t * original_ttl = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*original_ttl);
    std::string original_ttl_str = std::to_string( ntohl(*original_ttl) );

    int32_t * signature_exp = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*signature_exp);
    std::string signature_exp_str = std::to_string( ntohl(*signature_exp) );
    
    int32_t * signature_inc = (int32_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*signature_inc);
    std::string signature_inc_str = std::to_string( ntohl(*signature_inc) );

    uint16_t* key_tag = (uint16_t*) (bytes + packet_offset_size);
    packet_offset_size += sizeof(*key_tag);
    std::string key_tag_str = std::to_string( ntohs(*key_tag) );

    std::string signer_name;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, signer_name, 0);

    std::string signature = base64_encode(bytes, end_of_rdata - packet_offset_size);

    std::ostringstream output;
    output << "\"" << type_covered_str << " "
                   << algorithm_str << " "
                   << labels_str << " "
                   << original_ttl_str << " "
                   << signature_exp_str << " "
                   << signature_inc_str << " "
                   << key_tag_str << " "
                   << signer_name << " "
                   << "( " << signature << " )" << "\"";

    return output.str();
}


std::string parse_dns_answer_rdata_dnskey(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length)
{
    size_t end_of_rdata = packet_offset_size + rdata_length;
    
    uint16_t* flags = (uint16_t*) (bytes + packet_offset_size);     // 2 octets
    packet_offset_size += sizeof(*flags);
    std::string flags_str = std::to_string( ntohs(*flags) );

    uint8_t* protocol = (uint8_t*) (bytes + packet_offset_size);    // 1 octet
    packet_offset_size += sizeof(*protocol);
    std::string protocol_str = std::to_string( *protocol );

    uint8_t* algorithm = (uint8_t*) (bytes + packet_offset_size);    // 1 octet
    packet_offset_size += sizeof(*algorithm);
    std::string algorithm_str = std::to_string( *algorithm );

    std::string public_key = base64_encode(bytes, end_of_rdata - packet_offset_size);

    std::ostringstream output;
    output << "\"" << flags_str << " "
                   << protocol_str << " "
                   << algorithm_str << " "
                   << "( " <<  public_key << " )" << "\"";

    return output.str();
}


std::string parse_dns_answer_rdata_nsec(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length)
{
    size_t end_of_rdata = packet_offset_size + rdata_length;

    std::string next_domain_name;
    packet_offset_size = parse_dns_name_field(bytes, packet_offset_size, next_domain_name, 0);
    
    std::string type_bit_maps_field;
    
    while(packet_offset_size < static_cast<int32_t>(end_of_rdata))
    {
        uint8_t* octet = (uint8_t*) (bytes + packet_offset_size);
        packet_offset_size += sizeof(*octet);

        type_bit_maps_field.append(std::to_string(*octet));
        type_bit_maps_field.append(" ");
    }

    std::ostringstream output;

    output << "\"" << next_domain_name << " "
                   << "( " << type_bit_maps_field << ")\"";

    return output.str();
}


std::string parse_dns_answer_rdata_ds(const u_char* bytes, int32_t packet_offset_size, uint16_t rdata_length)
{
    size_t end_of_rdata = packet_offset_size + rdata_length;

    uint16_t* key_tag = (uint16_t*) (bytes + packet_offset_size);     // 2 octets
    packet_offset_size += sizeof(*key_tag);
    std::string key_tag_str = std::to_string( ntohs(*key_tag) );

    uint8_t* algorithm = (uint8_t*) (bytes + packet_offset_size);     // 1 octet
    packet_offset_size += sizeof(*algorithm);
    std::string algorithm_str = std::to_string( *algorithm );

    uint8_t* digest_type = (uint8_t*) (bytes + packet_offset_size);     // 1 octet
    packet_offset_size += sizeof(*digest_type);
    std::string digest_type_str = std::to_string( *digest_type );

    std::string digest;

    while(packet_offset_size < static_cast<int32_t>(end_of_rdata))
    {
        uint8_t* octet = (uint8_t*) (bytes + packet_offset_size);
        packet_offset_size += sizeof(*octet);
        
        std::stringstream hexvalue;
        hexvalue << std::hex << (int) *octet << std::dec;
        digest.append(hexvalue.str());
    }

    std::ostringstream output;

    output << "\"" << key_tag_str << " "
                   << algorithm_str << " "
                   << digest_type_str << " "
                   << "( " << digest << " )\"";
    return output.str();
    
}
