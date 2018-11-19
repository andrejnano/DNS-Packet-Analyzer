#include <iostream>
#include <sstream>
#include "statistics.h"

extern std::vector<StatisticEntry> *Statistics;

/**
 * @brief store new statistic inside the statitistics vector
 * 
 * @param domain_name domain name from the DNS query
 * @param rr_type type of the DNS msg
 * @param rr_answer DNS response data
 */
void log_answer(std::string domain_name, std::string rr_type, std::string rr_answer)
{
    // search for the entry, if it already exists
    std::vector<StatisticEntry>::iterator it = Statistics->begin();
    while(it != Statistics->end())
    {   
        // if the exact entry already exists, increase it's count
        if ((it->get_domain_name() == domain_name) && (it->get_rr_type() == rr_type) && (it->get_rr_answer() == rr_answer))
        {
            it->increaseCount();
            return;
        }
        it++;
    }

    // not found -> create a new statistic entry
    StatisticEntry new_entry(domain_name, rr_type, rr_answer);
    Statistics->push_back(new_entry);
}


void print_statistics()
{
    if (Statistics)
    {
        std::vector<StatisticEntry>::iterator it = Statistics->begin();
        while(it != Statistics->end())
        {   
            std::cout << it->get_domain_name() << " " 
                    << it->get_rr_type() << " "
                    << it->get_rr_answer() << " "
                    << it->get_count() << std::endl;
            it++;
        }
    }
}

std::string return_statistics()
{

    std::ostringstream output;
    if (Statistics)
    {
        std::vector<StatisticEntry>::iterator it = Statistics->begin();
        while(it != Statistics->end())
        {   
            output << it->get_domain_name() << " " 
                    << it->get_rr_type() << " "
                    << it->get_rr_answer() << " "
                    << it->get_count() << std::endl;
            it++;
        }
        return output.str();
    }
    return "<empty>";
}