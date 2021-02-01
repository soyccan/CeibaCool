#ifndef _LOGIN_H_
#define _LOGIN_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

ngx_array_t *login_ceiba(ngx_pool_t *pool, ngx_log_t *log);

#endif