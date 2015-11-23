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
SUBDIRS = source

lib_LTLIBRARIES=libsnmp_plugin.la
libsnmp_plugin_la_CPPFLAGS= -D_ANSC_LINUX -D_ANSC_USER -D_ANSC_LITTLE_ENDIAN_ -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include
libsnmp_plugin_la_LDFLAGS= -lccsp_common -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lm
libsnmp_plugin_la_SOURCES= \
	source/SnmpPlugin/netSnmpTutorialMIB.c \
	source/SnmpPlugin/ccsp_mib_utilities.c \
	source/SnmpPlugin/ccsp_table_helper.c \
	source/SnmpPlugin/cosa_api.c \
	source/SnmpPlugin/ccsp_scalar_helper_access.c \
	source/SnmpPlugin/ccsp_table_helper_control.c \
	source/SnmpPlugin/ccsp_table_helper_access.c \
	source/SnmpPlugin/ccsp_mib_helper.c \
	source/SnmpPlugin/ccsp_scalar_helper_control.c \
	source/SnmpPlugin/ccsp_scalar_helper.c \
	source/SnmpPlugin/CcspSnmpPlugin.c
libsnmp_plugin_la_DEPENDENCIES= \
	source/custom/libsnmp_custom.la

libsnmp_plugin_la_LIBADD=$(libsnmp_plugin_la_DEPENDENCIES)
