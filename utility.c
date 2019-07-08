/*
 * Part of Very Secure FTPd
 * Licence: GPL v2
 * Author: Chris Evans
 * utility.c
 */

#include "utility.h"
#include "sysutil.h"
#include "str.h"
#include "defs.h"
#include "session.h"
#include "tunables.h"
#include "privsock.h"
#include "ssl.h"
#include <stdio.h>

#define DIE_DEBUG

static struct vsf_session *s_p_sess = NULL;

void
die_init(struct vsf_session *p_sess)
{
  s_p_sess = p_sess;
}

void
die(const char* p_text)
{
#ifdef DIE_DEBUG
  bug(p_text);
#endif
  vsf_sysutil_exit(2);
}

void
die2(const char* p_text1, const char* p_text2)
{
  struct mystr die_str = INIT_MYSTR;
  str_alloc_text(&die_str, p_text1);
  if (p_text2)
  {
    str_append_text(&die_str, p_text2);
  }
  else
  {
    str_append_text(&die_str, "(null)");
  }
  die(str_getbuf(&die_str));
}

void
bug(const char* p_text)
{
  /* Detect calls caused by failed logging from bug() itself
   * to prevent infinite loops */
  static int s_in_bug = 0;
  const unsigned int buffer_size = 256;
  char text_buffer[buffer_size];
  unsigned int text_len;

  if (s_in_bug)
	return;

  s_in_bug = 1;

  if (s_p_sess)
  {
    /* Try to write the message to logs */
    if (s_p_sess->vsftpd_log_fd != -1)
    {
      snprintf(text_buffer, buffer_size,
               "%s vsftpd [pid %d]: \"%s\" from \"%s\": %s",
               vsf_sysutil_get_current_date(), vsf_sysutil_getpid(),
               str_getbuf(&s_p_sess->user_str),
               str_getbuf(&s_p_sess->remote_ip_str), p_text);
      text_len = vsf_sysutil_strlen(text_buffer);
      vsf_sysutil_write_loop(s_p_sess->vsftpd_log_fd, text_buffer, text_len);
    }

    if (tunable_syslog_enable)
    {
      snprintf(text_buffer, buffer_size, "\"%s\" from \"%s\": %s",
               str_getbuf(&s_p_sess->user_str),
               str_getbuf(&s_p_sess->remote_ip_str), p_text);
      vsf_sysutil_syslog(text_buffer, 1);
    }
  }
  else
  {
    /* dummy logging before the system is fully set up */
    if (tunable_syslog_enable)
    {
      vsf_sysutil_syslog(p_text, 1);
    }
  }

  snprintf(text_buffer, buffer_size, "500 OOPS: %s\r\n", p_text);
  text_len = vsf_sysutil_strlen(text_buffer);

  /* Rats. Try and write the reason to the network for diagnostics */
  if (s_p_sess && s_p_sess->control_use_ssl)
  {
    if (s_p_sess->ssl_slave_active)
    {
      priv_sock_send_cmd(s_p_sess->ssl_consumer_fd, PRIV_SOCK_WRITE_USER_RESP);
      priv_sock_send_buf(s_p_sess->ssl_consumer_fd, text_buffer, text_len);
    }
    else
    {
      (void)ssl_write(s_p_sess->p_control_ssl, text_buffer, text_len);
    }
  }
  else
  {
    vsf_sysutil_activate_noblock(VSFTP_COMMAND_FD);
    (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, text_buffer, text_len);
  }
  vsf_sysutil_exit(2);
}

void
vsf_exit(const char* p_text)
{
  (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, p_text,
                                vsf_sysutil_strlen(p_text));
  vsf_sysutil_exit(0);
}

