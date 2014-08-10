#!/bin/sh -

user=$(whoami)
if [ "x$user" != "xroot" ]; then
    echo "ERROR: not run as root !!"
    exit 1
fi

export LD_LIBRARY_PATH=$PWD/libs:../
export SNMPDLMODPATH=$PWD/libs
# for apps like snmpget... source this file then
export MIBDIRS=$PWD/mibs
export MIBS=ALL

# use -f to let snmpd do not fork, 
# since if fork after Cosa_Init(), Dbus has some problem.
if [ "x$subagent" != "x" ]; then
    echo "NOTE: Running as subagent ..."
    # do not kill snmpd, may kill master
    sleep 1;
    ./snmpd -f -C -c 'snmpd.conf' -M './mibs' -Le -X -x $subagent
elif [ "x$master" != "x" ]; then
    killall snmpd && sleep 1
    ./snmpd -f -C -M './mibs' -Le \
            --rocommunity=public --rwcommunity=private \
            --master=agentx --agentXSocket=$master
else
    killall snmpd && sleep 1
    ./snmpd -f -C -c 'snmpd.conf' -M './mibs' -Le
fi

if [ ! $? -eq 0 ]; then
    echo "Fail to start snmpd !!"
    # do not exit the shell when 'source'
    #exit 1
fi

