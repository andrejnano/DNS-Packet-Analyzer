#ifndef STATISTICS_H_
#define STATISTICS_H_

#include <vector>
#include <string>

class StatisticEntry {
    private:
        std::string domain_name;
        std::string rr_type;
        std::string rr_answer;
        int count;
    public:
        StatisticEntry(std::string domain_name, std::string rr_type, std::string rr_answer) 
            : domain_name {domain_name}, rr_type {rr_type}, rr_answer {rr_answer}, count {1} {};

        std::string get_domain_name() { return domain_name; }
        std::string get_rr_type() { return rr_type; }
        std::string get_rr_answer() { return rr_answer; }
        int get_count() { return count; }
        void increaseCount() { count++; }
};


/**
 *  @brief Inserts new Statistic Entry into the Statistics vector, or increases the count if it exists
 * 
 *  @param domain_name
 *  @param rr_type
 *  @param rr_answer
 *
 */
void log_answer(std::string domain_name, std::string rr_type, std::string rr_answer);


/**
 *  @brief Print accumulated statistics to standard output
 * 
 */
void print_statistics();


/**
 *  @brief Returns accumulated statistics as a single string object
 *  
 *  @return string accumulated statistics
 */
std::string return_statistics();

#endif // STATISTICS_H_