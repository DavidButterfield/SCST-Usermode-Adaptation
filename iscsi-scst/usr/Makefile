#
#  Makefile for the user space part of iSCSI-SCST.
#
#  Copyright (C) 2007 - 2017 Vladislav Bolkhovitin
#  Copyright (C) 2007 - 2017 SanDisk Corporation
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

ifndef PREFIX
        PREFIX=/usr/local
endif

SRCS_D = iscsid.c iscsi_scstd.c conn.c session.c target.c message.c ctldev.c \
		log.c chap.c event.c param.c config.c isns.c md5.c sha1.c \
		misc.c
OBJS_D = $(SRCS_D:.c=.o)

SRCS_ADM = iscsi_adm.c param.c
OBJS_ADM = $(SRCS_ADM:.c=.o)

CFLAGS += -O2 -Wall -Wextra -Wstrict-prototypes -Wno-sign-compare \
	-Wimplicit-function-declaration -Wno-unused-parameter \
	-g -I../include -I$(SCST_INC_DIR)
CFLAGS += -D_GNU_SOURCE # required for glibc >= 2.8
CFLAGS += $(LOCAL_CFLAGS)
CFLAGS += $(EXTRA_WFLAGS)

PROGRAMS = iscsi-scstd iscsi-scst-adm
LIBS =

ifndef SCST_USERMODE
# Make daemon code its own executable, to talk to implementation in real kernel
all: $(PROGRAMS)
else
# Make a "library" of all the user daemon code, to be linked with the "kernel" code
all: iscsi-scstlib.o iscsi-scst-adm
iscsi-scstlib.o: .depend_d $(OBJS_D)
	$(LD) $(OBJS_D) $(LOCAL_LD_FLAGS) -r -o $@
endif

iscsi-scstd: .depend_d $(OBJS_D)
	$(CC) $(OBJS_D) $(LIBS) $(LOCAL_LD_FLAGS) $(LOCAL_LIBS) -o $@

iscsi-scst-adm: .depend_adm  $(OBJS_ADM)
	$(CC) $(OBJS_ADM) $(LIBS) $(LOCAL_LD_FLAGS) $(LOCAL_LIBS) -o $@

ifeq (.depend_d,$(wildcard .depend_d))
-include .depend_d
endif

ifeq (.depend_adm,$(wildcard .depend_adm))
-include .depend_adm
endif

%.o: %.c Makefile
	$(CC) -c -o $(@) $(CFLAGS) $(<)

.depend_d:
	$(CC) -M $(CFLAGS) $(SRCS_D) >$(@)

.depend_adm:
	$(CC) -M $(CFLAGS) $(SRCS_ADM) >$(@)

clean:
	rm -f *.o $(PROGRAMS) .depend*

extraclean: clean
	rm -f *.orig *.rej
