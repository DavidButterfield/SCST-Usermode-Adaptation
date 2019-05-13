/* UMC_app.c
 * Copyright 2019 David A. Butterfield
 *
 * Usermode Compatibility startup and shutdown --
 * Establishes "kernel" environment before starting the "application" module(s)
 */
#define TRACE_TRACE true
#include <mtelib.h>
#include <sys_debug.h>
#include <pthread.h>

#define NAME UMC_APP

extern int UMC_init(const char * procname);
extern int UMC_exit(void);

extern int SCST_init(void);
extern int SCST_exit(void);

extern int DRBD_init(void);
extern int DRBD_exit(void);

extern int tcmu_bio_init(void);
extern int tcmu_bio_exit(void);

/* Begin shutdown processing --
 * Module _exit function should disengage from dependencies before returning.
 * Shutdown ends when the last thread exits -- modules should initiate
 * shutdown of all their threads when their _exit() functions are called.
 */
static void
APP_shutdown(void)
{
    /* Order matters here -- earlier items depend on later items */
    trace("APP_shutdown calls SCST_exit()");
    SCST_exit();

    trace("XXX sleep(2)");
    sleep(2);

    trace("APP_shutdown calls DRBD_exit()");
    DRBD_exit();

    trace("XXX sleep(2)");
    sleep(2);

    trace("APP_shutdown calls tcmu_bio_exit()");
    tcmu_bio_exit();

    trace("XXX sleep(2)");
    sleep(2);

    trace("APP_shutdown calls UMC_exit()");
    UMC_exit();

    trace("XXX sleep(2)");
    sleep(2);

    trace("APP_shutdown finishing");
    sys_service_fini();	    /* frees memory allocator */
    MTE_sys_service_put(SYS_SERVICE);
    sys_service_set(NULL);

    pthread_exit(NULL);
}

/* Start a clean shutdown --
 * sigint_handler is invoked from the itqthread event loop,
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
	APP_shutdown();
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

    trace("XXX sleep(2)");
    sleep(2);

    trace("UMC_constructor calls tcmu_bio_init()");
    tcmu_bio_init();

    trace("XXX sleep(2)");
    sleep(2);

    trace("UMC_constructor calls DRBD_init()");
    DRBD_init();

    trace("XXX sleep(2)");
    sleep(2);

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
