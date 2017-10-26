//
// Created by sky on 15.10.17.
//

#ifndef SKYWIFI_SETTINGS_HPP
#define SKYWIFI_SETTINGS_HPP
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"

inline ptree loadFromFile(const char* filename );
inline std::string getValue( const char* option );

#include "settings.cpp"

#endif //SKYWIFI_SETTINGS_HPP
