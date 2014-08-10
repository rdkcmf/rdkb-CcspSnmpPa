SUBDIRS = source

lib_LTLIBRARIES=libsnmp_plugin.la
libsnmp_plugin_la_LDFLAGS=
libsnmp_plugin_la_SOURCES=
libsnmp_plugin_la_DEPENDENCIES= \
	source/SnmpPlugin/libCcspSnmpPa_SnmpPlugin.la \
	source/custom/libCcspSnmpPa_custom.la

libsnmp_plugin_la_LIBADD=$(libsnmp_plugin_la_DEPENDENCIES)
