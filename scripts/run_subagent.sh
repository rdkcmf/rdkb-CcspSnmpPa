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
if [ -f /etc/device.properties ]; then
      source /etc/device.properties
fi
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

if [ "$BOX_TYPE" = "XB3" ]; then
      ENABLE_SNMPv2=`syscfg get V2Support`
      echo "RFC value for SNMPV2 support is $ENABLE_SNMPv2 ."
fi

# copy ccsp_msg.cfg to /tmp, if it's not available there
if [ ! -f /tmp/ccsp_msg.cfg ]; then
	cp /usr/ccsp/ccsp_msg.cfg /tmp
fi

master=$1 # may empty

SNMP_PID=`ps -ww | grep snmp_subagent | grep -v cm_snmp_ma_2 | grep -v grep | awk '{print $1}'`
kill -9 $SNMP_PID

if [ "x$master" != "x" ]; then
      if [[ "$BOX_TYPE" = "XB3" && "$ENABLE_SNMPv2" = "true" || "$BOX_TYPE" != "XB3" ]]; then
             echo "starting snmp_subagent process with $master"
    	     ${BINPATH}/snmp_subagent -x $master
      fi
else
    echo "starting snmp_subagent"
    ${BINPATH}/snmp_subagent
fi

if [ ! $? -eq 0 ]; then
    echo "Fail to start subagent !!"
    # do not exit the shell when 'source'
    #exit 1
fi

