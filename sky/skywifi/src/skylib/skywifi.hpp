//
// Created by sky on 13.10.17.
//

#ifndef SKYWIFI_HPP
#define SKYWIFI_HPP
#include "boost/property_tree/ptree.hpp"
#include <autobahn.hpp>
using boost::property_tree::ptree;

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
        std::string signature;
        std::cerr << "responding to auth challenge: " << challenge.challenge() << std::endl;
        if ( challenge.authmethod() == "ticket" ) {
            signature = m_secret;
        } else {
            signature = compute_wcs(m_secret, challenge.challenge());
        }
        challenge_future.set_value(autobahn::wamp_authenticate(signature));
        std::cerr << "signature: " << signature << std::endl;
        return challenge_future.get_future();
    }
};

namespace skywifi {


    class status {
    public:
        boost::property_tree::ptree getNetStat();
        boost::property_tree::ptree getChilliClients();
        boost::property_tree::ptree getState();

    };


    class config {
    public:
        void getconfig(void);
    };

    class procedures {
    public:


    };


}

#include "skywifi.cpp"

#endif //SKYWIFI_HPP
