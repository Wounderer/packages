#include "skywifi.hpp"
using boost::property_tree::ptree;
namespace pt = boost::property_tree;

sky::Settings settings("/etc/config.json");

bool debug;
namespace sky {

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
        std::ofstream fileGreen( settings.get<std::string>("green_led") );
        std::ofstream fileRed( settings.get<std::string>("red_led") );
        fileGreen << "0";
        fileRed << "1";
        fileGreen.close();
        fileRed.close();
    }

    void led_green() {
        std::ofstream fileGreen( settings.get<std::string>("green_led") );
        std::ofstream fileRed( settings.get<std::string>("red_led") );
        fileGreen << "1";
        fileRed << "0";
        fileGreen.close();
        fileRed.close();
    }

    void led_off() {
        std::ofstream fileGreen( settings.get<std::string>("green_led") );
        std::ofstream fileRed( settings.get<std::string>("red_led") );
        fileGreen << "0";
        fileRed << "0";
        fileGreen.close();
        fileRed.close();
    }

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

/**
 * Установка конфигурации
 * @param invocation
 */
const void procedure_set_config( autobahn::wamp_invocation invocation ) {
    const std::string request_id = invocation->argument<std::string>(0);
    const std::string config_section = invocation->argument<std::string>(1);
    const std::string config_data = invocation->argument<std::string>(2);
    const std::string afterApply = invocation->argument<std::string>(3);
    if ( config_data.empty() || config_section.empty() ) {
        std::cerr << "Empty config or package name!" << std::endl;
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
            invocation->result( result );
}

void status_loop( boost::asio::deadline_timer* t) {
        boost::future<void> pub;
        autobahn::wamp_call_options call_options;
        call_options.set_timeout(std::chrono::seconds(10));
        std::tuple<std::string, uint, uint64_t, uint, uint> arguments( mac , sky::memUsage(), sessionid, sky::getUptime(), sky::getLoadAv());
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

int main(int argc, char** argv) {

    sky::led_off();

    debug = settings.get<bool>("debug");
    realm = settings.get<std::string>("realm");
    version = settings.get<std::string>("version");
    port = settings.get<int>("port");
    device_id = settings.get<int>("device_id");
    server = settings.get<std::string>("server");
    secret = settings.get<std::string>("secret");
    component_regdevice = settings.get<std::string>("component_regdevice");
    mac = settings.get<std::string>("mac");
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






                            autobahn::wamp_call_options call_options;
                            call_options.set_timeout(std::chrono::seconds(10));
                            pub = session->call("app.sharedpool.regdevice", make_tuple(mac,std::to_string( settings.get<int>("device_id") ),settings.get<std::string>("version"), std::to_string( sessionid )), call_options ).then(
                                    [&](boost::future<autobahn::wamp_call_result> result){
                                        bool b_reg_Result = result.get().argument<bool>(0);
                                        if ( b_reg_Result ) {
                                            std::cerr << "Device registered succesfull" << std::endl;
                                        } else {
                                            io.stop(); // ? Просто ошибка регистрации, в принципе не критичная
                                        }
                                        //regdevice( result.get().argument<std::map<std::string, std::string>>(0) );
                                    });
                            pub.get();
                            session->provide("app.device."+ std::to_string(sessionid)+".get_config", &procedure_get_config).then(
                                    boost::launch::deferred,
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        registration.get();
                                    });
                            session->provide("app.device."+ std::to_string(sessionid)+".set_config", &procedure_set_config).then(
                                    boost::launch::deferred,
                                    [&](boost::future<autobahn::wamp_registration> registration) {
                                        registration.get();
                                    });
                            t.async_wait(boost::bind(status_loop,&t) );

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