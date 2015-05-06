#!/bin/sh -

#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################


#user=$(whoami)
#if [ "x$user" != "xroot" ]; then
#    echo "ERROR: not run as root !!"
#    exit 1
#fi

# change to subagent directory first
cd /fss/gw/usr/share/snmp

export LD_LIBRARY_PATH=$PWD/libs:../:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/fss/gw/usr/ccsp/:/fss/gw/lib/:/fss/gw/usr/lib/
export SNMPDLMODPATH=$PWD/libs
# for apps like snmpget... source this file then
export MIBDIRS=$PWD/mibs
export MIBS=ALL

# copy ccsp_msg.cfg to /tmp, if it's not available there
if [ ! -f /tmp/ccsp_msg.cfg ]; then
	cp /fss/gw/usr/ccsp/ccsp_msg.cfg /tmp
fi

master=$1 # may empty

killall snmp_subagnet ; sleep 1
if [ "x$master" != "x" ]; then
    ./snmp_subagnet -x $master
else
    ./snmp_subagnet
fi

if [ ! $? -eq 0 ]; then
    echo "Fail to start subagent !!"
    # do not exit the shell when 'source'
    #exit 1
fi

