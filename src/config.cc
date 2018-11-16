#include "config.h"

void Config::setPcap(std::string value)
{
    // check for validity of the string
    this->pcap = value;
    pcapSet = true;
}

void Config::setInterface(std::string value)
{
    this->interface = value;
    interfaceSet = true;
}

void Config::setSyslog(std::string value)
{
    this->syslog = value;
    syslogSet = true;
}

void Config::setTime(std::string value)
{
    this->time = value;
    timeSet = true;
}