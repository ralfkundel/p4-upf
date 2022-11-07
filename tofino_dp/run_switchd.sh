#!/bin/sh
# set SDE and SDE_INSTALL variable to default values
: ${SDE=/opt/bf-sde-9.7.2}
: ${SDE_INSTALL=$SDE/install}

$SDE/run_switchd.sh -c compile/upf.conf
