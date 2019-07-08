#ifndef VSF_UTILITY_H
#define VSF_UTILITY_H

struct mystr;
struct vsf_session;

/* die_init
 * PURPOSE
 * Initialize static pointer to vsf_session used for
 * logging and SSL support used by die() and bug().
 * If not set (or set to NULL) only dummy write
 * to VSFTP_COMMAND_FD will be done.
 * PARAMETERS
 * p_sess       - pointer to vsf_session or NULL
 */
void die_init(struct vsf_session *p_sess);

/* die()
 * PURPOSE
 * Terminate execution of the process, due to an abnormal (but non-bug)
 * situation.
 * PARAMETERS
 * p_text       - text string describing why the process is exiting
 */
void die(const char* p_text);

/* die2()
 * PURPOSE
 * Terminate execution of the process, due to an abnormal (but non-bug)
 * situation.
 * PARAMETERS
 * p_text1      - text string describing why the process is exiting
 * p_text2      - text to safely concatenate to p_text1
 */
void die2(const char* p_text1, const char* p_text2);

/* bug()
 * PURPOSE
 * Terminate execution of the process, due to a suspected bug, trying to emit
 * the reason this happened down the network in FTP response format.
 * PARAMETERS
 * p_text       - text string describing what bug trap has triggered
 *       */
void bug(const char* p_text);

/* vsf_exit()
 * PURPOSE
 * Terminate execution of the process, writing out the specified text string
 * in the process.
 * PARAMETERS
 * p_text       - text string describing why the process is exiting
 */
void vsf_exit(const char* p_text);

#endif

