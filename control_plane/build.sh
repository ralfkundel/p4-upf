#!/bin/bash
add_sudo_rights() {
  current_user=$USER 
  if (sudo -l | grep -q '(ALL : ALL) NOPASSWD: '$1); then 
    echo 'visudo entry already exists for: '${1};  
  else
    sleep 0.1
    echo $current_user' ALL=(ALL:ALL) NOPASSWD:'$1 | sudo EDITOR='tee -a' visudo; 
  fi
}

go mod tidy

add_sudo_rights $(which arp);

rm p4upf
go build -o p4upf src/main.go
