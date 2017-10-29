//
// Created by sky on 29.10.17.
//

#ifndef CROSSBAR_SKY_SKYWIFI_HPP
#define CROSSBAR_SKY_SKYWIFI_HPP

#include <boost/property_tree/ptree.hpp>
#include "boost/property_tree/json_parser.hpp"

using boost::property_tree::ptree;



namespace sky {

    void trim( std::string &s);

    void led_red();

    void led_green();

    void led_off();

    class Settings {
    public:
        Settings( std::string filename ){
            std::ifstream jsonFile( filename );
            read_json(jsonFile, this->currentSettings);
            jsonFile.close();
        }
        void loadSettings( char filename ) {

        };
        template < typename Type >
        Type get( std::string option ) {
            return this->currentSettings.get<Type>( option );
        }

    private:
        ptree currentSettings;
    };

};


#endif //CROSSBAR_SKY_SKYWIFI_HPP
