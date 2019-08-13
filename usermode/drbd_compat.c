/* drbd_compat.c
 * Compatibility for DRBD running in usermode
 * Copyright 2019 David A. Butterfield
 */
#define _GNU_SOURCE
#ifndef DRBD_COMPAT_H
#error Makefile failed to force-include drbd_compat.h as required
#endif

#include <sys_service.h>
#include "fuse_tree.h"

struct module UMC_DRBD_module = { .name = "drbd", .version = "UMC" };

/* Here we must know the names of all the DRBD params and init/fini functions */
extern void fuse_modparm_add_enable_faults(void);
extern void fuse_modparm_add_fault_rate(void);
extern void fuse_modparm_add_fault_count(void);
extern void fuse_modparm_add_fault_devs(void);
extern void fuse_modparm_add_disable_sendpage(void);
extern void fuse_modparm_add_allow_oos(void);
extern void fuse_modparm_add_minor_count(void);
extern void fuse_modparm_add_protocol_version_min(void);

extern error_t UMC_INIT_drbd_init(void);		/* drbd_main.c */
extern error_t UMC_INIT_dtt_initialize(void);		/* drbd_transport_tcp.c */

void
DRBD_init(void)
{
    error_t err;

    fuse_pde_mkdir(THIS_MODULE->name, NULL);

    /* Set up the /proc entries for these parameters */
    fuse_modparm_add_disable_sendpage();
    fuse_modparm_add_allow_oos();
    fuse_modparm_add_minor_count();
    fuse_modparm_add_protocol_version_min();
#ifdef CONFIG_DRBD_FAULT_INJECTION
    fuse_modparm_add_enable_faults();
    fuse_modparm_add_fault_rate();
    fuse_modparm_add_fault_count();
    fuse_modparm_add_fault_devs();
#endif

    /* Call the various module init functions -- we must know all their names here, which
     * are automatically generated by the module_init and module_exit macros
     */
    err = UMC_INIT_drbd_init();
    verify_noerr(err, "drbd_init()");

    err = UMC_INIT_dtt_initialize();
    verify_noerr(err, "dtt_initialize");
}

extern void fuse_modparm_remove_enable_faults(void);
extern void fuse_modparm_remove_fault_rate(void);
extern void fuse_modparm_remove_fault_count(void);
extern void fuse_modparm_remove_fault_devs(void);
extern void fuse_modparm_remove_disable_sendpage(void);
extern void fuse_modparm_remove_allow_oos(void);
extern void fuse_modparm_remove_minor_count(void);
extern void fuse_modparm_remove_protocol_version_min(void);

extern void UMC_EXIT_dtt_cleanup(void);
extern void UMC_EXIT_drbd_cleanup(void);

void
DRBD_exit(void)
{
    UMC_EXIT_dtt_cleanup();
    UMC_EXIT_drbd_cleanup();

#ifdef CONFIG_DRBD_FAULT_INJECTION
    fuse_modparm_remove_enable_faults();
    fuse_modparm_remove_fault_rate();
    fuse_modparm_remove_fault_count();
    fuse_modparm_remove_fault_devs();
#endif
    fuse_modparm_remove_disable_sendpage();
    fuse_modparm_remove_allow_oos();
    fuse_modparm_remove_minor_count();
    fuse_modparm_remove_protocol_version_min();

    fuse_pde_remove(THIS_MODULE->name, NULL);
}
