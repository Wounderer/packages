#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=99

start_service() {
    rm -f /etc/config/wireless
    wifi detect > /etc/config/wireless
    procd_open_instance skyagent
    procd_set_param command /bin/skywifi

    # respawn automatically if something died, be careful if you have an alternative process supervisor
    # if process dies sooner than respawn_threshold, it is considered crashed and after 5 retries the service is stopped
     procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-15} ${respawn_retry:-255}

    # procd_set_param env SOME_VARIABLE=funtimes  # pass environment variables to your process
    # procd_set_param limits core="unlimited"  # If you need to set ulimit for your process
    # procd_set_param file /var/etc/your_service.conf # /etc/init.d/your_service reload will restart the daemon if these files have changed
    procd_set_param netdev eth0 # likewise, except if dev\'s ifindex changes.
    # procd_set_param data name=value ... # likewise, except if this data changes.
    # procd_set_param stdout 1 # forward stdout of the command to logd
    # procd_set_param stderr 1 # same for stderr
    # procd_set_param user nobody # run service as user nobody
    procd_set_param pidfile /var/run/skyagent.pid # write a pid file on instance start and remote it on stop
    procd_close_instance
}
