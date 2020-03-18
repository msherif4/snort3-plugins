pkglib_LTLIBRARIES = daq_dpdk.la

daq_dpdk_la_SOURCES = daq_dpdk.c
daq_dpdk_la_CPPFLAGS = -DBUILDING_SO -Wall -ggdb -O3 -msse4.1
daq_dpdk_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(DAQ_MOD_LIBS)
