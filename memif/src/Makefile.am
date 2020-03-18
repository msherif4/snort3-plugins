pkglib_LTLIBRARIES = daq_memif.la

daq_memif_la_SOURCES = daq_memif.c
daq_memif_la_CFLAGS = -DBUILDING_SO -Wall -ggdb -DMAX_MEMIF_QUEUES=@MAX_MEMIF_QUEUES@
daq_memif_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(DAQ_MOD_LIBS)

