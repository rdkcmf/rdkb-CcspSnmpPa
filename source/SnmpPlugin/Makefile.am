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
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -DRDKB_MIB
AM_LDFLAGS = -lccsp_common
AM_LDFLAGS += -lnetsnmpmibs
AM_LDFLAGS += -ldl
AM_LDFLAGS += -lnetsnmpagent
AM_LDFLAGS += -lnetsnmp
AM_LDFLAGS +=
AM_LDFLAGS += -lm
AM_LDFLAGS += -lprint_uptime

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES=libsnmp_plugin.la
bin_PROGRAMS = snmp_subagent

snmp_subagent_CPPFLAGS = -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include $(CPPFLAGS)
snmp_subagent_SOURCES = ccsp_snmp_subagent.c

snmp_subagent_LDADD = libsnmp_plugin.la



libsnmp_plugin_la_CPPFLAGS= -D_ANSC_LINUX -D_ANSC_USER -D_ANSC_LITTLE_ENDIAN_ -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include
libsnmp_plugin_la_LDFLAGS= -lccsp_common -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lm -lprint_uptime -lsysevent -lutapi -lutctx

libsnmp_plugin_la_SOURCES= \
	ccsp_mib_utilities.c \
	ccsp_table_helper.c \
	cosa_api.c \
	ccsp_scalar_helper_access.c \
	ccsp_table_helper_control.c \
	ccsp_table_helper_access.c \
	ccsp_mib_helper.c \
	ccsp_scalar_helper_control.c \
	ccsp_scalar_helper.c \
	CcspSnmpPlugin.c
