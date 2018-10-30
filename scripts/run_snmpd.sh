#!/bin/sh -
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

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

