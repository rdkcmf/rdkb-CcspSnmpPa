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
AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libsnmp_custom.la

libsnmp_custom_la_CPPFLAGS = -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include
libsnmp_custom_la_SOURCES = rg_hotspot_handler.c rg_firewall_handler.c rg_wifi_handler.c rg_ipmgmt_handler.c ccsp_snmp_common.c rg_devmgmt_handler.c rg_ntpserver_handler.c rg_moca_handler.c rg_wandns_handler.c rg_diag_handler.c

libsnmp_custom_la_DEPENDENCIES= \
      ${top_builddir}/source/SnmpPlugin/libsnmp_plugin.la

libsnmp_custom_la_LDFLAGS = -lccsp_common -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lm $(libsnmp_custom_la_DEPENDENCIES)
