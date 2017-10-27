//
// Created by sky on 13.10.17.
//

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread.hpp>
#include "settings.hpp"
#include <stdint.h>
#include <stdio.h>
#include <sys/sysinfo.h>

namespace pt = boost::property_tree;
using boost::property_tree::ptree;

class sysinfo sys_info;


namespace skywifi {

    inline int usage() {
        std::cerr << "Usage: skylib [connect|config|status]" << std::endl;
        return -1;
    }

    boost::property_tree::ptree skywifi::status::getNetStat() {
        boost::property_tree::ptree stateTree;
        return stateTree;
    }
    boost::property_tree::ptree skywifi::status::getChilliClients() {
        boost::property_tree::ptree stateTree;
        return stateTree;
    }

    boost::property_tree::ptree skywifi::status::getState() {
        boost::property_tree::ptree stateTree;
        stateTree.add_child("network", skywifi::status::getNetStat() );
        stateTree.add_child("chilli", skywifi::status::getChilliClients() );
        return stateTree;
    }

    inline std::string getOption( std::string option )  {
        try {
            std::ifstream jsonFile("/etc/config.json");
            ptree pt;
            read_json(jsonFile, pt);
            std::string val = pt.get<std::string>(option);
            return val;
        } catch (const std::exception& e) {
            std::cerr <<  e.what() << std::endl;
            return 0;
        }
    }

    inline int getIntOption( std::string option )  {
        try {
            std::ifstream jsonFile("/etc/config.json");
            ptree pt;
            read_json(jsonFile, pt);
            int val = pt.get<int>(option);
            return val;
        } catch (const std::exception& e) {
            std::cerr <<  e.what() << std::endl;
            return 0;
        }
    }
    inline bool getBoolOption( std::string option )  {
        try {
            std::ifstream jsonFile("/etc/config.json");
            ptree pt;
            read_json(jsonFile, pt);
            bool val = pt.get<bool>(option);
            return val;
        } catch (const std::exception& e) {
            std::cerr <<  e.what() << std::endl;
            return 0;
        }
    }


}
