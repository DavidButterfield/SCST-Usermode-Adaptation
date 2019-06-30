/* UMC_app.c
 * Copyright 2019 David A. Butterfield
 *
 * Usermode Compatibility startup and shutdown --
 * This is the file that knows about all the various pieces being brought together.
 * Establishes "kernel" environment before starting the "application" module(s).
 */
#include <mtelib.h>
#include <sys_debug.h>
#include <pthread.h>

#define NAME UMC_APP

#define MODULE_NAME_LEN                 56  //XXX
#define MODULE_ARCH_INIT                0xED0CBAD0  /*  DAB's "usermode arch" */    //XXX
struct module { char name[MODULE_NAME_LEN]; int arch; string_t version; };
struct module __this_module = { .name = "SCST/DRBD", .arch = MODULE_ARCH_INIT, .version = "ZERO" };

/* Usermode compatibility for kernel code */
extern error_t UMC_init(char * procname);
extern error_t UMC_exit(void);

/* SCST iSCSI storage server */
extern error_t SCST_init(void);
extern error_t SCST_exit(void);

/* Distributed Replicated Block Device */
extern error_t DRBD_init(void);
extern error_t DRBD_exit(void);

/* bio interface to TCMU backstore handlers */
extern error_t tcmu_bio_init(void);
extern error_t tcmu_bio_exit(void);

/* Don't want to #include usermode_lib.h here */
extern void __attribute__((__noreturn__)) do_exit(long);
extern struct task_struct * UMC_run_shutdown(error_t (*fn)(void * env), void * env);

/* Final shutdown on a thread that does not depend on UMC services */
static void *
MTE_shutdown(void * not_used)
{
    sleep(1);
    trace("Shutdown finishing");
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
    trace("APP_shutdown calls SCST_exit()");
    SCST_exit();
    trace("XXX sleep(2)"); sleep(2);

    trace("APP_shutdown calls DRBD_exit()");
    DRBD_exit();
    trace("XXX sleep(2)"); sleep(2);

    trace("APP_shutdown calls tcmu_bio_exit()");
    tcmu_bio_exit();
    trace("XXX sleep(2)"); sleep(2);

    trace("APP_shutdown calls UMC_exit()");
    UMC_exit();
    trace("XXX sleep(2)"); sleep(2);

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
	sys_warning("Recursive SIGINT->UMC_shutdown ignored");
    } else {
	shutdown_started = true;
	sys_notice("Shutdown initiated by SIGINT");

	/* Drive the shutdown from an independent kthread */
	UMC_run_shutdown(APP_shutdown, NULL);
    }
}

/* Master init() call for all the kernel modules running in usermode */
__attribute__((__constructor__))	/* runs before main() is called */
static void
UMC_constructor(void)
{
    errno_t err;
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

    /* Order matters here -- later items depend on earlier items */
    trace("UMC_constructor calls UMC_init()");
    err = UMC_init("/fuse/scst/proc");	//XXXX need a separate dir for DRBD
    verify_noerr(err, "UMC_init");

    trace("UMC_constructor calls tcmu_bio_init()");
    tcmu_bio_init();

    trace("UMC_constructor calls DRBD_init()");
    DRBD_init();

    trace("UMC_constructor calls SCST_init()");
    SCST_init();

    trace("UMC_constructor done");
}

__attribute__((__destructor__))	    /* runs after exit() is called */
static void
UMC_destructor(void)
{
    sys_breakpoint();
}
