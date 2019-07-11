# SCST/usermode/tcmur/Makefile

TCMU_CFLAGS += -I. #XXX?

OBJS += rbd.o
OBJS += ram.o
OBJS += glfs.o
OBJS += qcow.o
OBJS += spdk.o
OBJS += bio_tcmu.o

all:
	@echo "usermode/tcmur/Makefile should be called from usermode/Makefile"

tcmur:	$(OBJS)

%.o: %.c
	$(CC) -c -o $(@) $(TCMU_CFLAGS) $(<)

# XXX Do dependencies right

bio_tcmu.o: bio_tcmu.c
	$(CC) -c -o $(@) $(TCMU_CFLAGS) -I$(USERMODE_LIB_SRC)/arch/x86/include -I$(USERMODE_LIB_SRC)/include $(<)

ram.o:	scsi_defs.h bio_tcmu.h ram.c tcmu-runner.h libtcmu.h

rbd.o:	scsi_defs.h bio_tcmu.h rbd.c tcmu-runner.h libtcmu.h

glfs.o:	scsi_defs.h bio_tcmu.h darray.h glfs.c tcmu-runner.h libtcmu.h

qcow.o:	scsi_defs.h bio_tcmu.h qcow.c qcow.h qcow2.h tcmu-runner.h libtcmu.h

spdk.o: spdk.c spdk/stdinc.h spdk/nvme.h spdk/env.h tcmu-runner.h libtcmu.h

clean:
	rm -rf *.o

extraclean: clean

help:
	@echo sudo apt install librbd-dev
	@echo sudo apt install libglusterfs-dev

.PHONY:	all tcmur clean extraclean help
