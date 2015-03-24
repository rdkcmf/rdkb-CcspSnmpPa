SUBDIRS = source

lib_LTLIBRARIES=libsnmp_plugin.la
libsnmp_plugin_la_CPPFLAGS= -D_ANSC_LINUX -D_ANSC_USER -D_ANSC_LITTLE_ENDIAN_ -D_COSA_SIM_ -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include
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
