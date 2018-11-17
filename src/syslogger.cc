#include "syslogger.h"
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define PORT 514

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

            // create socket
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

void SysLogger::dispatch(std::string message)
{

    switch(this->server_address_family)
    {
        case AF_INET:
        {
            int rv = sendto( this->socket_fd, 
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