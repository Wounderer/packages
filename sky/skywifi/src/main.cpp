#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <tuple>
#include <boost/property_tree/ptree.hpp>
#include <boost/asio.hpp>
#include <boost/atomic.hpp>
#include "autobahn/autobahn.hpp"
#include <msgpack.hpp>
#include <sys/sysinfo.h>
#include <linux/types.h>
#include "boost/property_tree/json_parser.hpp"
#include <boost/thread.hpp>
#include <stdexcept>
#include <stdio.h>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "skywifi.hpp"

using boost::property_tree::ptree;

namespace pt = boost::property_tree;

sky::Settings settings("/etc/config.json");

bool debug;

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

    return str;
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

void getMac() {
    std::ifstream t(settings.get<std::string>("mac_file"));
    std::stringstream buffer;
    buffer << t.rdbuf();
    mac = buffer.str();
    sky::trim( mac );
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

void on_events( const autobahn::wamp_event& event ) {
    std::size_t id = event.number_of_arguments();
    char args = event.argument<char>(id);
    try {
        std::cerr << "joined: " << args << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }
}
std::shared_ptr<auth_wamp_session> session;

const void procedure_get_config( autobahn::wamp_invocation invocation ) {
    auto package = invocation->argument<std::string>(0);
    std::map<std::string, std::string> result;
    result[package] = getConfig(package);
    invocation->result( std::make_tuple (result) );
}

void status_loop( boost::asio::deadline_timer* t) {

        boost::future<void> pub;
        autobahn::wamp_call_options call_options;
        call_options.set_timeout(std::chrono::seconds(10));
        std::tuple<std::string, uint, uint64_t> arguments( mac , memUsage(), sessionid );
        pub = session->call("app.sharedpool.report", arguments, call_options).then([&](boost::future<autobahn::wamp_call_result> result){
            try {
                bool accepted = result.get().argument<bool>(0);
                if ( accepted && debug ) {
                    std::cerr << "Report accepted" << std::endl;
                } else {
                    std::cerr << "Report error" << std::endl;
                }
            } catch (const std::exception& e) {
                if ( debug ) {
                    std::cerr << "call failed: " << e.what() << std::endl;
                }
                return;
            }
        });
        t->expires_at(t->expires_at() + boost::posix_time::seconds(10));
        t->async_wait(boost::bind(status_loop,t));

}

void regdevice( std::map<std::string, std::string> config ) {
    setConfig( "network", config["network"] );
    setConfig( "wireless", config["wireless"] );
    setConfig( "system", config["system"] );
    setConfig( "chilli", config["chilli"] );
    setConfig( "firewall", config["firewall"] );
    system("/etc/init.d/network reload");
    system("wifi down && wifi up");

};


int main(int argc, char** argv) {

    sky::led_off();

    getMac();


    debug = settings.get<bool>("debug");
    realm = settings.get<std::string>("realm");
    version = settings.get<std::string>("version");
    port = settings.get<int>("port");
    device_id = settings.get<int>("device_id");
    server = settings.get<std::string>("server");
    secret = settings.get<std::string>("secret");
    component_regdevice = settings.get<std::string>("component_regdevice");
    boost::asio::io_service io;
    boost::asio::deadline_timer t(io, boost::posix_time::seconds(10));
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
                    std::cerr << e.what() << std::endl;
                    sky::led_red();
                    io.stop();
                    return;
                }
                std::cerr << "connected" << std::endl;

                start_future = session->start().then([&](boost::future<void> started) {

                    std::cerr << "started" << std::endl;
                    std::vector<std::string> authmethods = { "wampcra" };
                    join_future = session->join(realm, authmethods, mac).then([&](boost::future<uint64_t> joined) {
                        try {
                            std::cerr << "joined realm: " << std::endl;
                            sessionid = joined.get();
                            sky::led_green();
                            std::cerr << "sessionid: " << sessionid << std::endl;




                            provide_config_request = session->provide("app.device."+ std::to_string(sessionid)+".getconfig", &procedure_get_config).then(
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        try {
                                            registration.get();
                                            std::cerr << "registered get_config:" << registration.get().id() << std::endl;
                                        } catch (const std::exception& e) {
                                            std::cerr << e.what() << std::endl;
                                        }
                                    });

                            autobahn::wamp_call_options call_options;
                            call_options.set_timeout(std::chrono::seconds(10));
                            //std::tuple<std::string, int,std::string> arguments( mac, device_id, version );
                            std::map<std::string, std::string> arguments;
                            arguments["id"] = mac;
                            arguments["device_id"] = std::to_string( settings.get<int>("device_id") );
                            arguments["fw_version"] = settings.get<std::string>("server");
                            pub = session->call("app.sharedpool.regdevice", make_tuple( arguments), call_options ).then(
                                    [&](boost::future<autobahn::wamp_call_result> result){
                                        regdevice( result.get().argument<std::map<std::string, std::string>>(0) );
                                    });
                            t.async_wait(boost::bind(status_loop,&t) );
                            pub.get();

                        }
                        catch (const std::exception& e) {
                            std::cerr << e.what() << std::endl;
                            io.stop();
                            sky::led_red();
                            return;
                        }
                    });
                    try {
                        std::cerr << "starting.." << std::endl;
                        started.get();
                        std::cerr << "Ok?" << std::endl;
                    } catch (const std::exception& e) {
                        std::cerr << e.what() << std::endl;
                        io.stop();
                        sky::led_red();
                        return;
                    }
                });

            });
    io.run();
    sky::led_off();
    exit(1);
}