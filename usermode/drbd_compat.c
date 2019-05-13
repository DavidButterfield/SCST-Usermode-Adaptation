/* drbd_compat.c
 * Compatibility for DRBD running in usermode
 * Copyright 2019 David A. Butterfield
 */
#define NAME DRBD_COMPAT

#ifndef DRBD_COMPAT_H
#error Makefile failed to force-include drbd_compat.h as required
#endif

#include <sys_service.h>
#include <sys_debug.h>

extern void UMC_param_create_enable_faults(void);
extern void UMC_param_create_fault_rate(void);
extern void UMC_param_create_fault_count(void);
extern void UMC_param_create_fault_devs(void);
extern void UMC_param_create_disable_sendpage(void);
extern void UMC_param_create_allow_oos(void);
extern void UMC_param_create_minor_count(void);
extern void UMC_param_create_protocol_version_min(void);

extern errno_t UMC_INIT_drbd_init(void);		/* drbd_main.c */
extern errno_t UMC_INIT_dtt_initialize(void);		/* drbd_transport_tcp.c */

void
DRBD_init(void)
{
    errno_t err;

    /* Set up the /proc entries for these parameters */
    UMC_param_create_disable_sendpage();
    UMC_param_create_allow_oos();
    UMC_param_create_minor_count();
    UMC_param_create_protocol_version_min();
#ifdef CONFIG_DRBD_FAULT_INJECTION
    UMC_param_create_enable_faults();
    UMC_param_create_fault_rate();
    UMC_param_create_fault_count();
    UMC_param_create_fault_devs();
#endif

    /* Call the various module init functions -- we must know all their names here, which
     * are automatically generated by the module_init and module_exit macros
     */
    err = UMC_INIT_drbd_init();
    verify_noerr(err, "drbd_init()");

    err = UMC_INIT_dtt_initialize();
    verify_noerr(err, "dtt_initialize");
}

extern void UMC_param_remove_enable_faults(void);
extern void UMC_param_remove_fault_rate(void);
extern void UMC_param_remove_fault_count(void);
extern void UMC_param_remove_fault_devs(void);
extern void UMC_param_remove_disable_sendpage(void);
extern void UMC_param_remove_allow_oos(void);
extern void UMC_param_remove_minor_count(void);
extern void UMC_param_remove_protocol_version_min(void);

extern void UMC_EXIT_dtt_cleanup(void);
extern void UMC_EXIT_drbd_cleanup(void);

void
DRBD_exit(void)
{
    UMC_EXIT_dtt_cleanup();
    UMC_EXIT_drbd_cleanup();

#ifdef CONFIG_DRBD_FAULT_INJECTION
    UMC_param_remove_enable_faults();
    UMC_param_remove_fault_rate();
    UMC_param_remove_fault_count();
    UMC_param_remove_fault_devs();
#endif
    UMC_param_remove_disable_sendpage();
    UMC_param_remove_allow_oos();
    UMC_param_remove_minor_count();
    UMC_param_remove_protocol_version_min();
}
