/* UMC_app.c
 * Copyright 2019 David A. Butterfield
 *
 * Usermode Compatibility startup and shutdown --
 * This is the file that knows about all the various pieces being brought together.
 * Establishes "kernel" environment before starting the "application" module(s).
 */
#define _GNU_SOURCE
#include <features.h>
#include <errno.h>
#include <mtelib.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#include "UMC_assert.h"

#define pr_warning(fmtargs...)		fprintf(stderr, "WARNING: "fmtargs)
#define pr_notice(fmtargs...)		fprintf(stderr, "NOTICE: "fmtargs)
#define trace_app(fmtargs...)	    //	fprintf(stderr, ""fmtargs)

#define UMC_FUSE_MOUNT_POINT_DEFAULT	"/UMCfuse"
#define UMC_FUSE_MOUNT_POINT_ENV	"UMC_FS_ROOT"

/* Usermode compatibility for kernel code */
extern error_t UMC_init(const char * procname);
extern error_t UMC_exit(void);

/* SCST iSCSI storage server */
extern error_t SCST_init(void);
extern error_t SCST_exit(void);

/* Distributed Replicated Block Device */
extern error_t DRBD_init(void);
extern error_t DRBD_exit(void);

/* bio interface to TCMU backstore handlers */
extern error_t bio_tcmur_init(void);
extern error_t bio_tcmur_exit(void);

/* Don't want to #include usermode_lib.h here */
extern void __attribute__((__noreturn__)) do_exit(long);
extern struct task_struct * UMC_run_shutdown(error_t (*fn)(void * env), void * env);

/* Final shutdown on a thread that does not depend on UMC services */
static void *
MTE_shutdown(void * not_used)
{
    sleep(1);
    trace_app("Shutdown finishing");

    sys_service_fini();	    /* frees memory allocator */

    MTE_sys_service_put(SYS_SERVICE);
    sys_service_set(NULL);
    pthread_exit(NULL);
}

/* Begin shutdown processing on shutdown thread */
static error_t
APP_shutdown(void * not_used)
{
    /* Order matters here -- earlier items depend on later items */
    trace_app("APP_shutdown calls SCST_exit()");
    SCST_exit();
    trace_app("sleep(1)"); sleep(1);

    trace_app("APP_shutdown calls DRBD_exit()");
    DRBD_exit();
    trace_app("sleep(1)"); sleep(1);

    trace_app("APP_shutdown calls UMC_exit()");
    UMC_exit();
    trace_app("sleep(1)"); sleep(1);

    /* Start the SYS shutdown thread */
    pthread_t pthr;
    pthread_create(&pthr, NULL, MTE_shutdown, NULL);

    /* Exit the APP shutdown thread */
    do_exit(0);
}

/* Start a clean shutdown --
 * sigint_handler is invoked from the irqthread event loop,
 * not an asynchronous signal delivery.
 */
static void
sigint_handler(uint32_t signum)
{
    static bool shutdown_started = false;
    expect_eq(signum, SIGINT);

    if (shutdown_started) {
	pr_warning("Recursive SIGINT->UMC_shutdown ignored\n");
    } else {
	shutdown_started = true;
	pr_notice("Shutdown initiated by SIGINT\n");

	/* Drive the shutdown from an independent kthread */
	UMC_run_shutdown(APP_shutdown, NULL);
    }
}

/* Master init() call for all the kernel modules running in usermode */
__attribute__((__constructor__))	/* runs before main() is called */
static void
UMC_constructor(void)
{
    error_t err;
    sys_service_set(MTE_sys_service_get());	/* install MTE as sys_service provider */
    sys_service_init(NULL/*cfg*/);  /* initialize sys_service provider, sys_thread_current */
    /*** Now we have a memory allocator ***/

    /* SIGINT received via signalfd, so disable normal delivery */
    sigset_t fd_sig;
    sigemptyset(&fd_sig);
    sigaddset(&fd_sig, SIGINT);
    err = pthread_sigmask(SIG_BLOCK, &fd_sig, NULL);
    expect_noerr(err, "pthread_sigmask");

    /* Direct these signals from signalfd to our handlers */
    mte_signal_handler_set(SIGINT, sigint_handler);

    /* Compute the mount point for the fuse fs */
    const char * mount_point = getenv(UMC_FUSE_MOUNT_POINT_ENV);
    if (!mount_point)
	mount_point = UMC_FUSE_MOUNT_POINT_DEFAULT;

    /* Order matters here -- later items depend on earlier items */
    trace_app("UMC_constructor calls UMC_init()");
    err = UMC_init(mount_point);
    verify_noerr(err, "UMC_init");

    trace_app("UMC_constructor calls DRBD_init()");
    DRBD_init();

    trace_app("UMC_constructor calls SCST_init()");
    SCST_init();

    trace_app("UMC_constructor done");
}

__attribute__((__destructor__))	    /* runs after exit() is called */
static void
UMC_destructor(void)
{
}
