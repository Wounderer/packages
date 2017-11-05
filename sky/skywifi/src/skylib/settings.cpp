//
// Created by sky on 15.10.17.
//

#include "settings.hpp"
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"
namespace pt = boost::property_tree;
using boost::property_tree::ptree;



inline ptree loadFromFile(const char* filename ) {
    ptree current_settings;
    std::ifstream jsonFile( filename );
    read_json(jsonFile, current_settings);
    return current_settings;
}

inline std::string getValue( const char* option ) {
    return settings.get_value( option );
}
