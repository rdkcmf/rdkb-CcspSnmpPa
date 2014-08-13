SUBDIRS = source

lib_LTLIBRARIES=libsnmp_plugin.la
libsnmp_plugin_la_CPPFLAGS= -D_ANSC_LINUX -D_ANSC_USER -D_ANSC_LITTLE_ENDIAN_ -D_COSA_SIM_ -I/var/tmp/pc-rdkb/include -I/var/tmp/pc-rdkb/include/net-snmp -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/tls/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/web/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/stun/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/slap/components/SlapVarConverter -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include
libsnmp_plugin_la_LDFLAGS= -L$(top_srcdir)/../CcspCommonLibrary/lib -lccsp_common -L/var/tmp/pc-rdkb/lib -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lcrypto -lm
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
