#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <Security/Security.h>

#include <dispatch/dispatch.h>
#include <stdio.h>

int main() {
  const char *host = "vpn-cn.ecnu.edu.cn";
  const char *port = "443";

  nw_endpoint_t endpoint = nw_endpoint_create_host(host, port);
  nw_parameters_t params = nw_parameters_create_secure_tcp(
      ^(nw_protocol_options_t tls_options) {
        sec_protocol_options_t sec =
            nw_tls_copy_sec_protocol_options(tls_options);
        sec_protocol_options_set_min_tls_protocol_version(
            sec, tls_protocol_version_TLSv12);
        sec_protocol_options_set_tls_server_name(sec, host);
      },
      NW_PARAMETERS_DEFAULT_CONFIGURATION);

  nw_connection_t conn = nw_connection_create(endpoint, params);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block bool ready = false;
  __block int err_code = 0;

  nw_connection_set_queue(
      conn, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
  nw_connection_set_state_changed_handler(
      conn, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_ready) {
          ready = true;
          dispatch_semaphore_signal(sem);
        } else if (state == nw_connection_state_failed ||
                   state == nw_connection_state_cancelled) {
          if (error)
            err_code = nw_error_get_error_code(error);
          dispatch_semaphore_signal(sem);
        }
      });

  nw_connection_start(conn);
  const long timed = dispatch_semaphore_wait(
      sem, dispatch_time(DISPATCH_TIME_NOW, 15ull * NSEC_PER_SEC));
  if (timed != 0) {
    printf("TIMEOUT\n");
    nw_connection_cancel(conn);
    return 2;
  }
  if (ready) {
    printf("READY\n");
    nw_connection_cancel(conn);
    return 0;
  }
  printf("FAILED code=%d\n", err_code);
  nw_connection_cancel(conn);
  return 1;
}
