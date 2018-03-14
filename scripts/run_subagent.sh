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


#user=$(whoami)
#if [ "x$user" != "xroot" ]; then
#    echo "ERROR: not run as root !!"
#    exit 1
#fi
BINPATH="/usr/bin"
source /etc/utopia/service.d/log_capture_path.sh
# change to subagent directory first
cd /usr/ccsp/snmp

export LD_LIBRARY_PATH=$PWD/libs:../:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/ccsp/:/lib/:/usr/lib/
export SNMPDLMODPATH=$PWD/libs\

# RDKB-4368 : SNMP agent not logging
export LOG4C_RCPATH=/fss/gw/rdklogger

# for apps like snmpget... source this file then
export MIBDIRS=$PWD/mibs
export MIBS=ALL

# copy ccsp_msg.cfg to /tmp, if it's not available there
if [ ! -f /tmp/ccsp_msg.cfg ]; then
	cp /usr/ccsp/ccsp_msg.cfg /tmp
fi

master=$1 # may empty

if [ "$2" != "selfheal_snmpv2" ];then
	killall snmp_subagent ; sleep 1
fi

if [ "x$master" != "x" ]; then
    echo "starting snmp_subagent process with $master"
    ${BINPATH}/snmp_subagent -x $master
else
    echo "starting snmp_subagent"
    ${BINPATH}/snmp_subagent
fi

if [ ! $? -eq 0 ]; then
    echo "Fail to start subagent !!"
    # do not exit the shell when 'source'
    #exit 1
fi

