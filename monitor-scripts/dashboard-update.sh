#!/bin/bash
service=$(cat /var/dashboard/services/dashboard-update | tr -d '\n')

if [[ $service == 'start' ]]; then
  echo 'running' > /var/dashboard/services/dashboard-update
  wget https://raw.githubusercontent.com/MzTechnology97/PiscesQoLDashboard_log/main/update.sh -O - | sudo bash
fi
