/**
 *  @file       config.cc
 *  @author     Andrej Nano (xnanoa00)
 *  @date       2018-11-19
 *  @version    1.0
 * 
 *  @brief  DNS protocol information export using the Syslog protocol | ISA 2018/19 (Export DNS informací pomocí protokolu Syslog)
 *  
 *  @section Description
 *  This program creates statistics about DNS communication and exports them to a syslog server.
 */

#include <unistd.h>
#include "config.h"
#include "misc.h"

// commonly used std objects.. really no need to be careful about poluting namespace
using std::cout;
using std::cerr;
using std::endl;
using std::string;

//---------------------
// basic setters
//------------------

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


std::unique_ptr<Config> parseArguments(int argc, char **argv)
{

    if (argc > 9) // too many args
    {
        std::cerr << "Wrong number of arguments." << std::endl;
        return nullptr;
    }

    // new configuration
    //auto tmpConfig = make_unique<Config>();
    std::unique_ptr<Config> tmpConfig (new Config);

    // utility variable
    char c;
    
    // disable getopt errors
    opterr = 0;

    while ((c = getopt(argc, argv, "r:i:s:t:")) != -1)
    {
        switch(c)
        {
            case 'r':
                tmpConfig->setPcap(optarg);
                break;
            case 'i':
                tmpConfig->setInterface(optarg);
                break;
            case 's':
                tmpConfig->setSyslog(optarg);
                break;
            case 't':
                tmpConfig->setTime(optarg);
                break;
            case '?':
                if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't')
                    std::cerr << RED << "ERROR" << RESET << ": Option -" << static_cast<char>(optopt) << " requires an argument." << endl;
                else if (isprint(optopt))
                   std::cerr << RED << "ERROR" << RESET << ": Uknown argument option '-" << static_cast<char>(optopt) << "'" << endl;
                else
                    std::cerr << RED << "ERROR" << RESET << ": Unknown argument option character. " << endl;
                exit(1); break;
            default:
                std::cerr << RED << "ERROR" << RESET << ": Unknown getopt() error occured." << std::endl;
                exit(1); break;
        }
    }

    // check for invalid argument combinations
    if (tmpConfig->isInterfaceSet() && tmpConfig->isPcapSet())
    {
        std::cerr << RED << "ERROR" << RESET << ": both -i && -r arguments cannot be combined." << std::endl;
        return nullptr;
    }
    
    // check for pcap + time combination which is ivalid
    if (tmpConfig->isPcapSet() && tmpConfig->isTimeSet())
    {
        std::cerr << RED << "ERROR" << RESET << ": -r && -t arguments cannot be combined." << std::endl;
        return nullptr;
    }

    if ((!tmpConfig->isPcapSet() && !tmpConfig->isInterfaceSet() && tmpConfig->isSyslogSet()) ||
        (!tmpConfig->isPcapSet() && !tmpConfig->isInterfaceSet() && tmpConfig->isTimeSet()))
    {
        std::cerr << RED << "ERROR" << RESET << ": either -i or -r must be set." << std::endl;
        return nullptr;
    }

    return tmpConfig;
}