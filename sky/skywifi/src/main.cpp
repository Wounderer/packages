#include "skywifi.hpp"
#include <syslog.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <stdbool.h>

using boost::property_tree::ptree;

namespace pt = boost::property_tree;
ptree settings;
bool debug;

void write_log( const std::string logcontent ) {
    const char * msg = logcontent.c_str();
    openlog("skywifi", 0, LOG_USER);
    syslog(LOG_NOTICE, msg);
    closelog();
    if ( debug ) {
        std::cout << msg << std::endl;
    }
}





namespace sky {

    const void red( int value ) {
        std::ofstream fileRed;
        fileRed.open( settings.get<std::string>("red_led") );
        fileRed << std::to_string( value ).c_str();
        fileRed.close();
    }

    const void green( int value ) {
        std::ofstream fileRed;
        fileRed.open( settings.get<std::string>("green_led") );
        fileRed << std::to_string( value ).c_str();
        fileRed.close();
    }

    void ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
            return !std::isspace(ch);
        }));
    }

    unsigned long memUsage() {
        struct sysinfo si;
        if (sysinfo(&si) != 0)
        {
            return 1;
        }
        unsigned long result = si.freeram * si.mem_unit;
        return result;
    }

    unsigned long getUptime() {
        struct sysinfo si;
        if (sysinfo(&si) != 0)
        {
            return 1;
        }
        unsigned long result = si.uptime;
        return result;
    }

    unsigned long getLoadAv() {
        struct sysinfo si;
        if (sysinfo(&si) != 0)
        {
            return 1;
        }
        unsigned long result = si.loads[1];
        return result;
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
        red(1);
        green(0);
    }

    void led_green() {
        red(0);
        green(1);
    }

    void led_off() {
        red(0);
        green(0);
    }



}

std::string GetEnv(const std::string& variable_name,const std::string& default_value)
{
    const char* value = getenv(variable_name.c_str());
    return value ? value : default_value;
}

void make_default_settings() {
    write_log("Getting settings");
    ptree default_settings;
    default_settings.add("server", GetEnv( "sky_server","80.93.182.86") );
    default_settings.add("port", GetEnv( "sky_port",std::to_string(8000) ) );
    default_settings.add<bool>("leds",true);
	default_settings.add("realm",GetEnv("sky_realm","realm1"));
    default_settings.add("debug", true);
	default_settings.add("red_led",GetEnv("sky_red_led","/sys/devices/platform/ath79-gpio/gpio/gpio2/value"));
	default_settings.add("green_led",GetEnv("sky_green_led","/sys/class/leds/rb:green:port5/brightness"));
	default_settings.add("mac_file",GetEnv("sky_mac_file","/sys/class/net/eth0/address"));
	default_settings.add("secret",GetEnv("sky_secret","secret123"));
    default_settings.add("salt" ,"dgfngvbu");
	default_settings.add("version",GetEnv("PKG_VERSION","1.5.4"));
    default_settings.add("device_id",1);
    default_settings.add("report_interval",20);
	default_settings.add("component_auth",GetEnv("sky_component_auth","app.sharedpool.auth"));
	default_settings.add("component_report",GetEnv("sky_component_report","app.sharedpool.report"));
	default_settings.add("component_regdevice",GetEnv("sky_component_regdevice","app.sharedpool.regdevice"));
	default_settings.add("component_captivesession",GetEnv("sky_component_captivesession","app.sharedpool.captivesession"));
	default_settings.add("component_logger",GetEnv("sky_component_captivesession","app.sharedpool.log"));

    std::ifstream macFile( default_settings.get<std::string>("mac_file").c_str() );
    std::stringstream buffer;
    buffer << macFile.rdbuf();
    std::string def_auth_id = buffer.str();
    sky::trim( def_auth_id );
    macFile.close();
    default_settings.add("auth_id",GetEnv("SKY_AGENT_CUSTOM_AUTHID", def_auth_id));
    std::string filename = "config.json";
    std::ofstream filestr( filename.c_str() );
    write_json( filestr, default_settings );
}

std::string realm,server,secret,component_regdevice, mac, version;
uint64_t sessionid, device_id;
short unsigned int port;


inline void setConfig( std::string package, std::string config ) {
    std::string filename = "/etc/config/" + package;
    std::ofstream filestr( filename.c_str() );
    filestr << config;
}



inline std::string getConfig( std::string package ) {
    std::string filename = "/etc/config/" + package;
    std::ifstream t(filename);
    std::string str;

    t.seekg(0, std::ios::end);
    str.reserve(t.tellg());
    t.seekg(0, std::ios::beg);

    str.assign((std::istreambuf_iterator<char>(t)),
               std::istreambuf_iterator<char>());
    write_log("Responding config file for package " + package);
    return str;
}

class auth_wamp_session :
        public autobahn::wamp_session
{
public:
    boost::promise<autobahn::wamp_authenticate> challenge_future;
    std::string m_secret;

    auth_wamp_session(
            boost::asio::io_service& io,
            bool debug_enabled,
            const std::string& secret)
            : autobahn::wamp_session(io, debug_enabled)
            , m_secret(secret)
    {
    }

    boost::future<autobahn::wamp_authenticate> on_challenge(const autobahn::wamp_challenge& challenge)
    {
        std::cerr << "responding to auth challenge: " << challenge.challenge() << std::endl;
        std::string signature = compute_wcs(m_secret, challenge.challenge());
        challenge_future.set_value(autobahn::wamp_authenticate(signature));
        std::cerr << "signature: " << signature << std::endl;
        return challenge_future.get_future();
    }
};


std::shared_ptr<auth_wamp_session> session;

/**
 * cats 1 = wamp 2 = system 3 = captive
 * levels 1 public 2 protected 3 private 4 debug
 * [authid, sessionid, category, level, message]
 */
void wamp_log(const std::string msg, int msg_cat = 1, int msg_lvl = 1) {
    autobahn::wamp_call_options call_options;
    call_options.set_timeout(std::chrono::seconds(10));
    std::tuple<std::string, uint64_t, int, int, std::string> arguments( mac , sessionid, msg_cat, msg_lvl, msg);
    session->call("app.sharedpool.log", arguments, call_options).then(
            boost::launch::deferred,
            [&](boost::future<autobahn::wamp_call_result> result){
                std::cerr << "oki" << std::endl;
            });
}

/**
 * Установка конфигурации
 * @param invocation
 */
void procedure_set_config( autobahn::wamp_invocation invocation ) {
    const std::string request_id = invocation->argument<std::string>(0);
    const std::string config_section = invocation->argument<std::string>(1);
    const std::string config_data = invocation->argument<std::string>(2);
    const std::string afterApply = invocation->argument<std::string>(3);
    if ( config_data.empty() || config_section.empty() ) {
        write_log("Empty config or package name! in received config");
        return;
    } else {
        setConfig( config_section, config_data );
    }
    std::string afterApplyResult;
    if ( !afterApply.empty() ) {
         afterApplyResult = system(afterApply.c_str());
    } else {
        afterApplyResult = "done";
    }
    wamp_log("New configuration for section: "+config_section, 1, 1);
    invocation->result( std::make_tuple (request_id, afterApplyResult) );
}

/**
 * Полученние конфигурации из файла
 * @param invocation
 */
void procedure_get_config( autobahn::wamp_invocation invocation ) {
    const std::string request_id = invocation->argument<std::string>(0);
    const std::string config_section = invocation->argument<std::string>(1);
    std::string configSectionData = getConfig( config_section );
    std::vector <std::string>result = { request_id, configSectionData };
    wamp_log("Responding current confog for section: "+config_section, 1, 1);
    invocation->result( std::make_tuple (result) );
}


std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    return result;
}


void procedure_shell( autobahn::wamp_invocation invocation ) {
    wamp_log("Custom command execution", 1, 1);
    const std::string request_id = invocation->argument<std::string>(0);
    const std::string command = invocation->argument<std::string>(1);
    const std::string ShellOut = exec( command.c_str() );
    invocation->result( std::make_tuple (request_id, ShellOut) );
}


void status_loop( boost::asio::deadline_timer* t) {
        boost::future<void> pub;
        autobahn::wamp_call_options call_options;
        call_options.set_timeout(std::chrono::seconds(10));
        std::tuple<std::string, uint, uint64_t, uint, uint> arguments( mac , sky::memUsage(), sessionid, sky::getUptime(), sky::getLoadAv());
        pub = session->call("app.sharedpool.report", arguments, call_options).then([&](boost::future<autobahn::wamp_call_result> result){
            try {
                bool accepted = result.get().argument<bool>(0);
            } catch (const std::exception& e) {
                if ( debug ) {
                    write_log("Report loop error: " + std::string( e.what() ) );
                }
                return;
            }
        });
        t->expires_at(t->expires_at() + boost::posix_time::seconds(settings.get<int>("report_interval")));
        t->async_wait(boost::bind(status_loop,t));
}

void exit_normal( std::string reason = "Unknown reason" ) {
    wamp_log("Early exit: "+reason, 1, 1);
    sky::led_off();
    session->stop();
    write_log("Exit reason : " + reason );
    exit(0);
}

int main(int argc, char** argv) {
    make_default_settings();
    std::string filename = "config.json";
    std::ifstream settingstream(filename);
    read_json(settingstream, settings);

    sky::led_red();

    debug = settings.get<bool>("debug");
    realm = settings.get<std::string>("realm");
    version = settings.get<std::string>("version");
    port = settings.get<int>("port");
    device_id = settings.get<int>("device_id");
    server = settings.get<std::string>("server");
    secret = settings.get<std::string>("secret");
    component_regdevice = settings.get<std::string>("component_regdevice");
    mac = settings.get<std::string>("auth_id");
    boost::asio::io_service io;
    boost::asio::deadline_timer t( io, boost::posix_time::seconds(10) );



    auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(server), port);
    auto transport = std::make_shared<autobahn::wamp_tcp_transport>(io, endpoint, debug);
    session = std::make_shared<auth_wamp_session>(io, debug, secret);

    transport->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(session));
    boost::future<void> connect_future;
    boost::future<void> start_future;
    boost::future<void> join_future;
    boost::future<void> provide_config_request;
    boost::future<void> provide_future_auth;
    boost::future<void> provide_future_regdevice;
    boost::future<void> provide_future_captivesession;
    boost::future<void> sub_meta_join;
    boost::future<void> sub_meta_leave;
    boost::future<void> leave_future;
    boost::future<void> stop_future;
    boost::future<void> pub;
    boost::future<void> sub;

    connect_future = transport->connect().then(
            [&](boost::future<void> connected) {
                try {
                    connected.get();

                } catch (const std::exception& e) {
                    exit_normal(e.what());
                }
                write_log("Connected to server");
                sky::led_green();
                start_future = session->start().then([&](boost::future<void> started) {
                    write_log("Transport started" );
                    std::vector<std::string> authmethods = { "wampcra" };
                    join_future = session->join(realm, authmethods, mac).then([&](boost::future<uint64_t> joined) {
                        try {
                            sessionid = joined.get();
                            write_log("joined realm: " + realm + ", session id: " + std::to_string(sessionid) );
                            sky::led_green();
                            autobahn::wamp_call_options call_options;
                            call_options.set_timeout(std::chrono::seconds(10));
                            session->call("app.sharedpool.regdevice", make_tuple(mac,std::to_string( settings.get<int>("device_id") ),settings.get<std::string>("version"), std::to_string( sessionid )), call_options ).then(
                                    [&](boost::future<autobahn::wamp_call_result> result){
                                        bool b_reg_Result = result.get().argument<bool>(0);
                                        if ( b_reg_Result ) {
                                            write_log( "Device registered succesfull");
                                        } else {
                                            exit_normal("registration failed");
                                        }
                                    });
                            session->provide("app.device."+ std::to_string(sessionid)+".get_config", &procedure_get_config).then(
                                    boost::launch::deferred,
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        registration.get();
                                        write_log("get_config procedure registered");
                                    });
                            session->provide("app.device."+ std::to_string(sessionid)+".set_config", &procedure_set_config).then(
                                    boost::launch::deferred,
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        registration.get();
                                        write_log("set_config procedure registered");
                                    });
                            session->provide("app.device."+ std::to_string(sessionid)+".shell", &procedure_shell).then(
                                    boost::launch::deferred,
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        registration.get();
                                        write_log("Virtual shell console registered");
                                    });
                            t.async_wait(boost::bind(status_loop,&t) );

                        }
                        catch (const std::exception& e) {
                            exit_normal("join realm failed: " +  std::string(e.what()) );
                        }
                    });
                    try {
                        started.get();
                        sky::led_green();
                    } catch (const std::exception& e) {
                        exit_normal("Transport start failed " +  std::string(e.what()) );
                    }
                });

            });
    try {
        io.run();
    } catch ( std::exception &e ) {
        std::string exc = e.what();
        exit_normal("Exception: " + exc);
    }

}