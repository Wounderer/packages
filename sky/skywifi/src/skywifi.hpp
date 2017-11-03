//
// Created by sky on 29.10.17.
//

#ifndef CROSSBAR_SKY_SKYWIFI_HPP
#define CROSSBAR_SKY_SKYWIFI_HPP

#include <boost/property_tree/ptree.hpp>
#include "boost/property_tree/json_parser.hpp"
#include <sys/sysinfo.h>
#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <tuple>
#include <boost/asio.hpp>
#include <boost/atomic.hpp>
#include "autobahn/autobahn.hpp"
#include <linux/types.h>
#include <boost/thread.hpp>
#include <stdexcept>
#include <stdio.h>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
using boost::property_tree::ptree;


namespace sky {

    void trim( std::string &s);

    void led_red();

    void led_green();

    void led_off();

    void ltrim(std::string &s);
    void rtrim(std::string &s);
    void trim(std::string &s);

    unsigned long memUsage();

    class Settings {
    public:
        Settings( std::string filename ){
            std::ifstream jsonFile( filename );
            read_json(jsonFile, this->currentSettings);
            jsonFile.close();
            std::ifstream macFile( this->currentSettings.get<std::string>("mac_file") );
            std::stringstream buffer;
            buffer << macFile.rdbuf();
            std::string mac = buffer.str();
            sky::trim( mac );
            this->currentSettings.add("mac", mac );
        }
        template < typename Type >
        Type get( std::string option ) {
            return this->currentSettings.get<Type>( option );
        }

    private:
        ptree currentSettings;
    };

}


#endif //CROSSBAR_SKY_SKYWIFI_HPP
