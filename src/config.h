#ifndef CONFIG_H_
#define CONFIG_H_

#include <iostream>
#include <string>

/**
 *      DNS Exporting configuration class 
 *      -> stores all run-time dependant variables from arguments
 */
class Config {
    private:
            std::string pcap;
            std::string interface;
            std::string syslog;
            std::string time;
            bool pcapSet;
            bool interfaceSet;
            bool syslogSet;
            bool timeSet;
    public:
        Config() : pcapSet {false}, interfaceSet {false}, syslogSet {false}, timeSet {false} {};

        void setPcap(std::string value);
        void setInterface(std::string value);
        void setSyslog(std::string value);
        void setTime(std::string value);

        std::string getPcap() { return pcap; }
        std::string getInterface() { return interface; }
        std::string getSyslog() { return syslog; }
        std::string getTime() { return time; }

        bool isPcapSet() { return pcapSet; }
        bool isInterfaceSet() { return interfaceSet; }
        bool isSyslogSet() { return syslogSet; }
        bool isTimeSet() { return timeSet; }
};

#endif // CONFIG_H_