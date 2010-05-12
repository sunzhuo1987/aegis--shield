## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${top_srcdir}/src/dynamic-preprocessors/libs

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_ssl_preproc.la

libsf_ssl_preproc_la_LDFLAGS = -export-dynamic

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c 

nodist_libsf_ssl_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c 

libsf_ssl_preproc_la_SOURCES = \
spp_ssl.c \
spp_ssl.h \
sf_preproc_info.h \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.c \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.h \
${top_srcdir}/src/dynamic-preprocessors/libs/sfparser.c \
${top_srcdir}/src/dynamic-preprocessors/libs/sfcommon.h

EXTRA_DIST = \
sf_ssl.dsp

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

all-local:
	$(MAKE) DESTDIR=$(PWD)/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c
