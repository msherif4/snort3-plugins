pkglib_LTLIBRARIES = logger_zmqfb.la

logger_zmqfb_la_SOURCES = zmqfb_logger.cc
logger_zmqfb_la_CPPFLAGS = -DBUILDING_SO -Wall -ggdb
logger_zmqfb_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(LOGGER_MOD_LIBS)

