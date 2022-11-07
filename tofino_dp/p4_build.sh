#!/bin/sh
# set SDE and SDE_INSTALL variable to default values
: ${SDE=/opt/bf-sde-9.7.2}
: ${SDE_INSTALL=$SDE/install}
mkdir -p compile
$SDE_INSTALL/bin/bf-p4c -v -o $PWD/compile/ p4_src/upf.p4
