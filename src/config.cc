#include "config.h"
#include <unistd.h>

// commonly used std objects.. really no need to be careful about poluting namespace
using std::cout;
using std::cerr;
using std::endl;
using std::string;

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
                    cerr << "Option -" << static_cast<char>(optopt) << " requires an argument." << endl;
                else if (isprint(optopt))
                    cerr << "Uknown option '-" << static_cast<char>(optopt) << "'" << endl;
                else
                    cerr << "Unknown option character. " << endl;
                exit(1); break;
            default:
                cerr << "Unknown getopt() error occured." << endl;
                exit(1); break;
        }
    }

    // check for invalid argument combinations
    if (tmpConfig->isInterfaceSet() && tmpConfig->isPcapSet())
    {
        std::cerr << "-i && -r sa navzajom vylucuju" << std::endl;
        return nullptr;
    }
    
    // check for pcap + time combination which is ivalid
    if (tmpConfig->isPcapSet() && tmpConfig->isTimeSet())
    {
        std::cerr << "-r && -t spolocne nemaju vyznam" << std::endl;
        return nullptr;
    }

    if ((!tmpConfig->isPcapSet() && !tmpConfig->isInterfaceSet() && tmpConfig->isSyslogSet()) ||
        (!tmpConfig->isPcapSet() && !tmpConfig->isInterfaceSet() && tmpConfig->isTimeSet()))
    {
        std::cerr << "-i alebo -r musi byt nastavene" << std::endl;
        return nullptr;
    }

    return tmpConfig;
}