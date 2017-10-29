//
// Created by sky on 29.10.17.
//
#include "skywifi.hpp"


namespace sky {

    sky::Settings settings("/etc/config.json");

    std::ofstream fileGreen( settings.get<std::string>("green_led") );
    std::ofstream fileRed( settings.get<std::string>("red_led") );

    void ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
            return !std::isspace(ch);
        }));
    }


    void rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
            return !std::isspace(ch);
        }).base(), s.end());
    }

    void trim(std::string &s) {
        sky::ltrim(s);
        sky::rtrim(s);
    }

    void led_red() {
        fileGreen << "0";
        fileRed << "1";
    }

    void led_green() {
        fileGreen << "1";
        fileRed << "0";
    }

    void led_off() {
        fileGreen << "0";
        fileRed << "0";
    }

}
