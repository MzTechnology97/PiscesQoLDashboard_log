#!/bin/bash
status=$(cat /var/dashboard/services/vpn | grep -Po "[^:]+" | head -n 1)
type=$(cat /var/dashboard/services/vpn | grep -Po "[^:]+" | tail -n 1)

if [[ $status == 'newconfig' ]]; then
  if [[ $type == 'pptp' ]]; then
    cp /var/dashboard/vpn/pptp_config /etc/ppp/peers/pisces
  else
    cp /var/dashboard/vpn/ovpn_config /etc/openvpn/pisces.conf
    cp /var/dashboard/vpn/auth.txt /etc/openvpn/auth.txt
  fi

  cat /var/dashboard/services/vpn | sed 's/newconfig/start/' | tee /var/dashboard/services/vpn
fi

if [[ $status == 'start' ]]; then
  if [[ $type == 'pptp' ]]; then
    systemctl stop openvpn@pisces
    systemctl disable openvpn@pisces

    pon pisces
  else
    poff pisces
    systemctl enable openvpn@pisces
    systemctl start openvpn@pisces
  fi

  cat /var/dashboard/services/vpn | sed 's/start/starting/' | tee /var/dashboard/services/vpn
fi

if [[ $status == 'starting' ]]; then
  if [[ $type == 'pptp' ]]; then
    ip=$(ip -f inet addr show ppp0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  else
    ip=$(ip -f inet addr show tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  fi

  if [[ ! -z "$ip" ]]; then
    bash /etc/monitor-scripts/external-ip.sh
    cat /var/dashboard/services/vpn | sed 's/starting/enabled/' | tee /var/dashboard/services/vpn
  fi
fi

if [[ $status == 'stop' ]]; then
  if [[ $type == 'pptp' ]]; then
    poff pisces
  else
    systemctl stop openvpn@pisces
    systemctl disable openvpn@pisces
  fi
  cat /var/dashboard/services/vpn | sed 's/stop/stopping/' | tee /var/dashboard/services/vpn
fi

if [[ $status == 'stopping' ]]; then
  if [[ $type == 'pptp' ]]; then
    ip=$(ip -f inet addr show ppp0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  else
    ip=$(ip -f inet addr show tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  fi

  if [[ -z "$ip" ]]; then
    cat /var/dashboard/services/vpn | sed 's/stopping/disabled/' | tee /var/dashboard/services/vpn
    bash /etc/monitor-scripts/external-ip.sh
  fi
fi


if [[ $status == 'enabled' ]]; then
  if [[ $type == 'pptp' ]]; then
    ip=$(ip -f inet addr show ppp0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  else
    ip=$(ip -f inet addr show tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
  fi

  if [[ -z "$ip" ]]; then
    bash /etc/monitor-scripts/external-ip.sh
    cat /var/dashboard/services/vpn | sed 's/enabled/disabled/' | tee /var/dashboard/services/vpn
  fi
fi
