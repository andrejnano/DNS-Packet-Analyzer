/**
 *  @file       dns-export.cc
 *  @author     Andrej Nano (xnanoa00)
 *  @date       2018-10-01
 *  @version    0.1
 * 
 *  @brief ISA 2018, Export DNS informací pomocí protokolu Syslog
 *  
 *  @section Description
 *  
 *  Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server. 
 *  TODO: remove unnecessary libraries
 */

// std libraries 
#include <memory>
#include <iostream>
#include <iomanip>
#include <string>
#include <unistd.h>
#include <vector>
#include <thread>
#include <chrono>

// networking libraries
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

// Linux specific
#ifdef __linux__   
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#endif

// commonly used std objects.. really no need to be careful about poluting namespace
using std::cout;
using std::cerr;
using std::endl;
using std::string;

// project header files
#include "config.h"
#include "pcap_analysis.h"
#include "statistics.h"

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

#ifndef PCAP_MAX_SNAPLEN
#define PCAP_MAX_SNAPLEN 65535
#endif

extern char *optarg;
extern int optind, opterr, optopt;

// all current statistics will be stored in this vector
std::vector<StatisticEntry> *Statistics;

void timer(int timer_time);
void sigusr_handler(int signum);
void interrupt_handler(int signum);

/**
 *  @brief Main entry point, handles common routine and then delegates to runtime modes. 
 *  
 *  @param argc number of string arguments pointed to by argv
 *  @param argv vector of string arguments passed to the program
 *  @return exit code as an int
 */
int main(int argc, char **argv)
{
    // setup signal handlers
    signal(SIGINT, interrupt_handler);
    signal(SIGUSR1, sigusr_handler);

    // parse arguments into a configuration of runtime
    auto config = parseArguments(argc, argv);
    if (!config) { return EXIT_FAILURE; }

    // error buffer and pcap stream handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle;

    // live pcap sniffing from the interface specified
    if (config->isInterfaceSet())
    {
        // setup live capture handle
        pcap_handle = pcap_create(config->getInterface().c_str(), errbuf);

        // set maximum snapshot length of the packet
        pcap_set_snaplen(pcap_handle, PCAP_MAX_SNAPLEN);
        // set immediate mode and disable timed buffering
        pcap_set_immediate_mode(pcap_handle, 1);
        
        // active the handle for live capture
        pcap_activate(pcap_handle);

        // create a DNS filter
        struct bpf_program dns_filter;
        const char dns_filter_string[] = "port 53";
        pcap_compile(pcap_handle, &dns_filter, dns_filter_string, 0, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(pcap_handle, &dns_filter);

        // create the statistics storage vector
        Statistics = new std::vector<StatisticEntry>;

        // setup timer
        auto timer_time = config->isTimeSet() ? std::stoi(config->getTime()) : 60;
        std::thread timer_thread(timer, timer_time);

        // get the link-layer header type for the live capture
        int link_type = pcap_datalink(pcap_handle);

        // analyze packets returned by the handle
        if (pcap_loop(pcap_handle, -1, pcap_analysis, reinterpret_cast<u_char*>(&link_type)) != 0)
        {
            std::cerr << "packet reading failed" << std::endl;
            return EXIT_FAILURE;
        }

        pcap_close(pcap_handle);
    }
    // offline pcap sniffing from the specified file
    else if (config->isPcapSet()) {

        // open the pcap stream from the file and assign to the handle
        if ( (pcap_handle = pcap_open_offline(config->getPcap().c_str(), errbuf)) == NULL)
        {
            std::cerr << "error opening the pcap file" << std::endl;
            return EXIT_FAILURE;
        }

        // init the statistics storage vector
        Statistics = new std::vector<StatisticEntry>;
        
        // get the link-layer header type for the ``savefile'
        uint16_t link_type = pcap_datalink(pcap_handle);

        // analyze packets returned by the handle
        if (pcap_loop(pcap_handle, -1, pcap_analysis, reinterpret_cast<u_char*>(&link_type)) != 0)
        {
            std::cerr << "packet reading failed" << std::endl;
            return EXIT_FAILURE;
        }

        pcap_close(pcap_handle);
    }

    print_statistics();
    return EXIT_SUCCESS;
}

/**
 *  @brief Properly handles interrupt, such as CTRL+C
 * 
 *  @param signum number of the signal caught
 *  @return void
 */
void interrupt_handler(int signum)
{
    cout << "\n\n[!!!] Caught signal(" << signum << "). Ending the program." << endl;
    print_statistics();
    exit(EXIT_SUCCESS);
}

/**
 *  @brief User signal handler
 * 
 *  @param signum number of the signal caught
 *  @return void
 */
void sigusr_handler(int signum)
{
    print_statistics();
}

void timer(int timer_time)
{
    if (timer_time > 0)
    {
        for(;;)
        {   
            // send statistics to the syslog server in consistent intervals
            std::this_thread::sleep_for (std::chrono::seconds(timer_time));
            print_statistics();
        }
    }
}