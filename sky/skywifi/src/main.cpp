#include <iostream>
#include <string>
#include <tuple>
#include "skylib/skywifi.hpp"
#include "skylib/settings.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/asio.hpp>
#include <boost/atomic.hpp>
#include <boost/thread.hpp>
#include <autobahn.hpp>
#include <msgpack.hpp>
#include <sys/sysinfo.h>
#include <linux/types.h>

using boost::property_tree::ptree;



std::string getState() {
    skywifi::status state;
    boost::property_tree::ptree current = state.getState();
    std::ostringstream currentstr;
    boost::property_tree::json_parser::write_json(currentstr, current);
    std::string inifile_text = currentstr.str();
    return inifile_text;
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

std::string getMac() {
    std::ifstream t("/sys/class/net/eth0/address");
    std::stringstream buffer;
    buffer << t.rdbuf();
    return buffer.str();
}



boost::future<void> status_loop( std::shared_ptr<auth_wamp_session> session ) {
    bool debug = skywifi::getBoolOption("debug");
    while (true)
    {

        boost::future<void> pub;

        autobahn::wamp_call_options call_options;
        call_options.set_timeout(std::chrono::seconds(10));
        std::tuple<std::string, uint> arguments( getMac() , memUsage() );
        pub = session->call("app.sharedpool.report", arguments, call_options).then([&](boost::future<autobahn::wamp_call_result> result){
            try {
                bool accepted = result.get().argument<bool>(0);
                if ( accepted && debug ) {
                    std::cerr << "Report accepted" << std::endl;
                }
            } catch (const std::exception& e) {
                if ( debug ) {
                    std::cerr << "call failed: " << e.what() << std::endl;
                }
                return;
            }
        });
        useconds_t interval = 2000000;
        usleep( interval );

        std::cerr << "Reporting status" << std::endl;
    }

}

void authenticate(autobahn::wamp_invocation invocation) {
    auto authid = invocation->argument<std::string>(1);
    std::map<std::string, std::string> result;
    result["secret"] = skywifi::getOption("secret");
    result["role"] = skywifi::getOption("role");
    result["salt"] = skywifi::getOption("salt");
    invocation->result (std::make_tuple (result));
}

void open_connection() {
    auto server = skywifi::getOption("server");
    short unsigned int port = skywifi::getIntOption("port");
    auto realm = skywifi::getOption("realm");
    boost::asio::io_service io;
    boost::future<void> f1, f2, f3;
    boost::future<void> subscribe_future;
    bool debug = skywifi::getBoolOption("debug");
    auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(server), port);
    auto transport = std::make_shared<autobahn::wamp_tcp_transport>(io, endpoint, debug);
    std::string secret = skywifi::getOption("secret");
    auto session = std::make_shared<auth_wamp_session>(io, debug, secret);
    transport->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(session));
    f1 = transport->connect().then([&](boost::future<void> connected) {
        connected.get();
        f2 = session->start().then(boost::launch::deferred,
             [&](boost::future<void> started) {
                started.get();
                 std::string authid = getMac();
                 std::vector<std::string> authmethods = { "wampcra" };
                 try {
                     f3 = session->join(realm, authmethods, authid).then(boost::launch::deferred,
                              [&](boost::future<uint64_t> joined) {
                                  autobahn::wamp_call_options call_options;
                                  call_options.set_timeout(std::chrono::seconds(10));
                                  std::tuple<std::string> arguments( getMac() );
                                  boost::future<void> pub;
                                  pub = session->call(skywifi::getOption("component_regdevice"), arguments, call_options).then([&](boost::future<autobahn::wamp_call_result> result){
                                      try {
                                          std::cerr <<  result.get().argument<std::string>(0).c_str()  << std::endl;

                                      } catch (const std::exception& e) {
                                          if ( debug ) {
                                              std::cerr << "call failed: " << e.what() << std::endl;
                                          }
                                          return;
                                      }
                                  });
                                  // Зарегистрировать процедуры тут

                                  // Запуск отправки отчета
                                  status_loop( session );
                                  joined.get();
                              });
                     f3.get();
                 } catch (const std::exception& e) {
                         std::cerr << e.what() << std::endl;
                         io.stop();
                         return;
                     }
             });
        f2.get();
    });
    io.run();

}


int main(int argc, char** argv) {
    open_connection();
}