/*
 *  Rewrite cookie of client on behalf of reverse proxy.
 *  Copyright (C) 2021 soyccan
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "login.h"
#include "utils.h"


static ngx_int_t ngx_ceibacool_handler(ngx_http_request_t *r);
static char *ngx_ceibacool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_ceibacool_commands[] = {

    {
        ngx_string("login_ceiba"),  // name

        // type
        NGX_CONF_NOARGS           // no arguments
            | NGX_HTTP_LOC_CONF   // "location" block
            | NGX_HTTP_LIF_CONF,  // "if" block under "location"

        ngx_ceibacool,  // callback
        0,              // where the directive's value is saved
        0,              // offset
        NULL            // post-processor (ngx_conf_post_t)
    },

    ngx_null_command};


static ngx_http_module_t ngx_ceibacool_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};


ngx_module_t ngx_ceibacool_module = {
    NGX_MODULE_V1,
    &ngx_ceibacool_module_ctx, /* module context */
    ngx_ceibacool_commands,    /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING};


static const ngx_str_t SET_COOKIE_LITERAL = ngx_string("Set-Cookie");
static const ngx_str_t LOCATION_LITERAL = ngx_string("Location");
static const ngx_str_t CEIBA_URL_LITERAL =
    ngx_string("https://ceiba.ntu.edu.tw/ChkSessLib.php");


/* header filter handler */

static ngx_int_t
ngx_ceibacool_handler(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http set_header handler");

    /* ignore client request body if any */

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // login ceiba and get cookie

    ngx_array_t *cookie_list = login_ceiba(r->pool, r->connection->log);
    ngx_str_t *cookie_list_elems = cookie_list->elts;

    // iterate over all obtained cookies, add them to response header

    log_debug(r->connection->log, "cookie_list:");
    for (ngx_uint_t i = 0; i < cookie_list->nelts; ++i) {
        log_debug(r->connection->log, "  cookie=%s", cookie_list_elems[i].data);

        /* add new array entry */
        ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key = SET_COOKIE_LITERAL;
        h->value = cookie_list_elems[i];
    }
    ngx_array_destroy(cookie_list);

    // send header

    // location
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key = LOCATION_LITERAL;
    h->value = CEIBA_URL_LITERAL;

    r->headers_out.status = NGX_HTTP_SEE_OTHER;
    r->headers_out.content_length_n = SET_COOKIE_LITERAL.len;

    ngx_int_t rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // send body

    ngx_buf_t *b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = SET_COOKIE_LITERAL.data;
    b->last = SET_COOKIE_LITERAL.data + SET_COOKIE_LITERAL.len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_ceibacool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_ceibacool_handler;

    ngx_log_stderr(0, "cf->log->level=%d\n", cf->log->log_level);

    return NGX_CONF_OK;
}

