AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -D_COSA_SIM_
AM_LDFLAGS = -L$(top_builddir)/../CcspCommonLibrary/lib
AM_LDFLAGS += -lccsp_common
AM_LDFLAGS += -L/var/tmp/pc-rdkb/lib
AM_LDFLAGS += -lnetsnmpmibs
AM_LDFLAGS += -ldl
AM_LDFLAGS += -lnetsnmpagent
AM_LDFLAGS += -lnetsnmp
AM_LDFLAGS += -lcrypto
AM_LDFLAGS += -lm

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libsnmp_custom.la
libsnmp_custom_la_CPPFLAGS = -I/var/tmp/pc-rdkb/include -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_builddir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_builddir)/../CcspCommonLibrary/source/ccsp/include -I$(top_builddir)/../CcspCommonLibrary/source/debug_api/include -I$(top_builddir)/../CcspCommonLibrary/source/cosa/include -I$(top_builddir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_builddir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_builddir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_builddir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/tls/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/web/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/stun/include -I$(top_builddir)/../CcspCommonLibrary/source/util_api/slap/components/SlapVarConverter -I$(top_builddir)/source/SnmpPlugin -I$(top_builddir)/source/include $(CPPFLAGS)
libsnmp_custom_la_SOURCES = rg_hotspot_handler.c rg_firewall_handler.c rg_wifi_handler.c rg_ipmgmt_handler.c ccsp_snmp_common.c rg_devmgmt_handler.c rg_ntpserver_handler.c rg_moca_handler.c rg_wandns_handler.c
libsnmp_custom_la_LDFLAGS =  -L$(top_builddir)/../CcspCommonLibrary/lib -lccsp_common -L/var/tmp/pc-rdkb/lib -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lcrypto -lm