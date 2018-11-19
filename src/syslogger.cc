#include "syslogger.h"
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


#define PORT 514        // SYSLOG DEFAULT 

// TODO: REFACTOR THIS :)

SysLogger::SysLogger(std::string syslog_server)
{
    memset(&this->server_address_ipv4, 0, sizeof(this->server_address_ipv4));
    memset(&this->server_address_ipv6, 0, sizeof(this->server_address_ipv6));

    // IPv4
    if (inet_pton( AF_INET, syslog_server.c_str(), &this->server_address_ipv4.sin_addr) != 0)
    {
        this->server_address_family = AF_INET;
    }
    // IPv6
    else 
    if (inet_pton( AF_INET6, syslog_server.c_str(), &this->server_address_ipv6.sin6_addr) != 0)
    {
        this->server_address_family = AF_INET6;
    }
    // Hostname
    else if ( (this->server_hostname = gethostbyname(syslog_server.c_str()) ) != NULL )
    {
        this->server_address_family = this->server_hostname->h_addrtype;
        switch(this->server_address_family)
        {
            case AF_INET:
            {
                memcpy(&this->server_address_ipv4.sin_addr, 
                        this->server_hostname->h_addr_list[0],
                        this->server_hostname->h_length);
                break;
            }
            case AF_INET6:
            {
                memcpy(&this->server_address_ipv6.sin6_addr, 
                        this->server_hostname->h_addr_list[0],
                        this->server_hostname->h_length);
                break;
            }
            default:
                std::cerr << "@hostname -> Invalid adress family!" << std::endl;
                exit(1);
        }
    }
    else
    {
        std::cerr << "could not resolve syslog server name" << std::endl;
        exit(1);
    }
    
    switch (this->server_address_family)
    {
        case AF_INET:
        {
            this->server_address_ipv4.sin_family = this->server_address_family;
            this->server_address_ipv4.sin_port = htons(PORT);

            // create UDP socket
            this->socket_fd = socket(this->server_address_family, SOCK_DGRAM, IPPROTO_UDP);
            if (socket_fd <= 0)
            {
                std::cerr << "Socket could not be created!" << std::endl;
                exit(1);
            }
            break;
        }
        case AF_INET6:
        {
            this->server_address_ipv6.sin6_family = this->server_address_family;
            this->server_address_ipv6.sin6_port = htons(PORT);
            // create socket
            this->socket_fd = socket(this->server_address_family, SOCK_DGRAM, IPPROTO_UDP);
            if (socket_fd <= 0)
            {
                std::cerr << "Socket could not be created!" << std::endl;
                exit(1);
            }
            break;
        }
        default:
            std::cerr << "Address family not set!" << std::endl;
            exit(1);
    }
}

SysLogger::~SysLogger()
{
    close(this->socket_fd);
}

void SysLogger::dispatch(std::string message, std::string executable, pid_t pid)
{
    // prepare message according to the Syslog RFC
    message = syslog_format(message, executable, pid);

    switch(this->server_address_family)
    {
        case AF_INET:
        {
            sendto( this->socket_fd, 
                    message.c_str(), 
                    message.length(), 
                    0,
                    (struct sockaddr *) &this->server_address_ipv4,
                    sizeof(this->server_address_ipv4));
            break;
        }
        case AF_INET6:
        {
            sendto( this->socket_fd, 
                    message.c_str(), 
                    message.length(), 
                    0, 
                    (struct sockaddr *) &this->server_address_ipv6,
                    sizeof(this->server_address_ipv6));
            break;
        }
        default:
            std::cerr << "errr.." << std::endl;
            exit(1);
    }

}

std::string SysLogger::syslog_format(std::string raw_message, std::string executable, pid_t pid)
{
    std::ostringstream output;
    const int facility = 16;    // local0
    const int severity =  6;    // Informational
    int priority = facility * 8 + severity;
    const int version = 1;
    
    time_t now = time(NULL);
    struct tm ts;
    char timestamp[80];
    ts = *localtime(&now);
    //strftime(timestamp, sizeof(timestamp), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &ts);
    uint16_t ms = ts.tm_sec % 1000;
    // timeval now;
    // gettimeofday(&now, NULL);
    // uint16_t ms = now.tv_usec / 1000;
    // char timestamp[80];
    // strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S")

    char hostname[255];
    gethostname(hostname, 255);

    output  << "<" << priority  << ">"
            << version << " "
            << timestamp << "." << std::setfill('0') << std::setw(3) << ms << "Z "
            << hostname << " "
            << executable << " "
            << pid << " "
            << "- - - " << raw_message;

    return output.str();
}
