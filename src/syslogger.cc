/**
 *  @file       syslogger.cc
 *  @author     Andrej Nano (xnanoa00)
 *  @date       2018-11-19
 *  @version    1.0
 * 
 *  @brief  DNS protocol information export using the Syslog protocol | ISA 2018/19 (Export DNS informací pomocí protokolu Syslog)
 *  
 *  @section Description
 *  This program creates statistics about DNS communication and exports them to a syslog server.
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include "syslogger.h"
#include "misc.h"

#define PORT 514        // SYSLOG DEFAULT PORT


/**
 * @brief Construct new syslogger, evaluate the syslog server name, prepare sockets
 * 
 * @param syslog_server address of the syslog server (hostname/ipv4/ipv6)
 */
SysLogger::SysLogger(std::string syslog_server)
{
    // reset the address structures 
    memset(&this->server_address_ipv4, 0, sizeof(this->server_address_ipv4));
    memset(&this->server_address_ipv6, 0, sizeof(this->server_address_ipv6));

    // try IPv4 address 
    if (inet_pton( AF_INET, syslog_server.c_str(), &this->server_address_ipv4.sin_addr))
    {
        this->server_address_family = AF_INET;
    }
    // try IPv6 address 
    else 
    if (inet_pton( AF_INET6, syslog_server.c_str(), &this->server_address_ipv6.sin6_addr))
    {
        this->server_address_family = AF_INET6;
    }
    // try Hostname address
    else if ( (this->server_hostname = gethostbyname(syslog_server.c_str()) ) != NULL )
    {
        // extract the address family type from the hostent structure
        this->server_address_family = this->server_hostname->h_addrtype;
        switch(this->server_address_family)
        {
            case AF_INET:   // IPv4
            {
                // extract the IP adress from the hostent structure
                memcpy(&this->server_address_ipv4.sin_addr, 
                        this->server_hostname->h_addr_list[0],
                        this->server_hostname->h_length);
                break;
            }
            case AF_INET6: // IPv6
            {
                // extract the IP adress from the hostent structure
                memcpy(&this->server_address_ipv6.sin6_addr, 
                        this->server_hostname->h_addr_list[0],
                        this->server_hostname->h_length);
                break;
            }
            default:
                std::cerr << RED << "ERROR" << RESET ": This hostname has an invalid address family." << std::endl;
                exit(1);
        }
    }
    else
    {
        std::cerr << RED << "ERROR" << RESET ": Could not resolve syslog server name." << std::endl;
        exit(1);
    }
    
    // depending on the address type
    switch (this->server_address_family)
    {
        case AF_INET:
        {
            // assign IP and PORT
            this->server_address_ipv4.sin_family = this->server_address_family;
            this->server_address_ipv4.sin_port = htons(PORT);

            // create UDP socket
            this->socket_fd = socket(this->server_address_family, SOCK_DGRAM, IPPROTO_UDP);
            if (socket_fd <= 0)
            {
                std::cerr << RED << "ERROR" << RESET ": Socket could not be created!" << std::endl;
                exit(1);
            }
            break;
        }
        case AF_INET6:
        {
            this->server_address_ipv6.sin6_family = this->server_address_family;
            this->server_address_ipv6.sin6_port = htons(PORT);
            
            // create UDP socket
            this->socket_fd = socket(this->server_address_family, SOCK_DGRAM, IPPROTO_UDP);
            if (socket_fd <= 0)
            {
                std::cerr << RED << "ERROR" << RESET ": Socket could not be created!" << std::endl;
                exit(1);
            }
            break;
        }
        default:
            std::cerr << RED << "ERROR" << RESET ": Address family not set!" << std::endl;
            exit(1);
    }
}

SysLogger::~SysLogger()
{
    // close the syslog communication socket
    close(this->socket_fd);
}

/**
 * @brief Send all statistics collected so far to the syslog server
 * 
 * @param message actual message data
 * @param executable name of the executable
 * @param pid process id
 */
void SysLogger::dispatch(std::string message, std::string executable, pid_t pid)
{
    // format the message according to the Syslog RFC
    message = syslog_format(message, executable, pid);

    // depending on the socket type.. (IPv4/IPv6)
    switch(this->server_address_family)
    {
        case AF_INET:
        {
            // send a single message
            int rv = sendto( this->socket_fd, 
                    message.c_str(), 
                    message.length(), 
                    0,
                    (struct sockaddr *) &this->server_address_ipv4,
                    sizeof(this->server_address_ipv4));

            if (rv < 0)
            {
                std::cerr << RED << "ERROR" << RESET ": Message could not be dispatched!" << std::endl;
            }
            break;
        }
        case AF_INET6:
        {
            // send a single message
            int rv = sendto( this->socket_fd, 
                    message.c_str(), 
                    message.length(), 
                    0, 
                    (struct sockaddr *) &this->server_address_ipv6,
                    sizeof(this->server_address_ipv6));
            if (rv < 0)
            {
                std::cerr << RED << "ERROR" << RESET ": Message could not be dispatched!" << std::endl;
            }
            break;
        }
        default:
            std::cerr << RED << "ERROR" << RESET ": Socket used by the SysLogger has unsupported address family assigned." << std::endl;
            exit(1);
    }

}

/**
 * @brief Syslof message formatting according to the RFC standard
 * 
 * @param raw_message actual message data
 * @param executable executable name
 * @param pid process id
 */
std::string SysLogger::syslog_format(std::string raw_message, std::string executable, pid_t pid)
{
    // output stream
    std::ostringstream output;

    // syslog msg options
    const int version = 1;
    const int facility = 16;    // local0
    const int severity =  6;    // Informational

    // priority is calculated
    int priority = facility * 8 + severity;

    // get the current time 
    time_t now = time(NULL);
    struct tm ts;
    char timestamp[80];
    ts = *localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &ts);   // format the datetime
    uint16_t ms = ts.tm_sec % 1000; // calculate miliseconds
   
    // get the hostname of the client
     char hostname[255];
    gethostname(hostname, 255);

    // concat to a single output string
    output  << "<" << priority  << ">"
            << version << " "
            << timestamp << "." << std::setfill('0') << std::setw(3) << ms << "Z "
            << hostname << " "
            << executable << " "
            << pid << " "
            << "- - - " << raw_message;

    return output.str();
}
