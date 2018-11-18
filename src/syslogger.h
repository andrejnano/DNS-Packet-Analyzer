#ifndef SYSLOGGER_H_
#define SYSLOGGER_H_

#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>

class SysLogger {
    private:
        int socket_fd;
        int server_address_family;
        struct sockaddr_in server_address_ipv4;
        struct sockaddr_in6 server_address_ipv6;
        struct hostent *server_hostname;

    public:
        SysLogger(std::string syslog_server);
        ~SysLogger();
        void dispatch(std::string message);
        std::string syslog_format(std::string raw_message);
};


#endif // SYSLOGGER_H_