AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -D_COSA_SIM_
AM_LDFLAGS = -lccsp_common
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
libsnmp_custom_la_CPPFLAGS = -I$(top_srcdir)/source/SnmpPlugin -I$(top_srcdir)/source/include $(CPPFLAGS)
libsnmp_custom_la_SOURCES = rg_hotspot_handler.c rg_firewall_handler.c rg_wifi_handler.c rg_ipmgmt_handler.c ccsp_snmp_common.c rg_devmgmt_handler.c rg_ntpserver_handler.c rg_moca_handler.c rg_wandns_handler.c
libsnmp_custom_la_LDFLAGS = -lccsp_common -lnetsnmpmibs -ldl -lnetsnmpagent -lnetsnmp -lcrypto -lm
