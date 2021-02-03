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


typedef struct {
    enum { SITE_UNDEFINED, SITE_CEIBA, SITE_COOL } site;
} ngx_http_ceibacool_loc_conf_t;


static ngx_int_t ngx_http_ceibacool_handler(ngx_http_request_t *r);
static void *ngx_http_ceibacool_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ceibacool_merge_loc_conf(ngx_conf_t *cf,
                                               void *parent,
                                               void *child);
static char *ngx_http_ceibacool_command_callback(ngx_conf_t *cf,
                                                 ngx_command_t *cmd,
                                                 void *conf);


static ngx_command_t ngx_http_ceibacool_commands[] = {

    {
        ngx_string("ceibacool"),  // name

        // type
        NGX_CONF_TAKE1            // no arguments
            | NGX_HTTP_LOC_CONF   // "location" block
            | NGX_HTTP_LIF_CONF,  // "if" block under "location"

        ngx_http_ceibacool_command_callback,  // callback
        NGX_HTTP_LOC_CONF_OFFSET,  // where the directive's value is saved
        offsetof(ngx_http_ceibacool_loc_conf_t, site),  // offset in structure
        NULL                                            // post-processor
    },

    ngx_null_command};


static ngx_http_module_t ngx_http_ceibacool_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_ceibacool_create_loc_conf, /* create location configuration */
    ngx_http_ceibacool_merge_loc_conf   /* merge location configuration */
};


ngx_module_t ngx_http_ceibacool_module = {
    NGX_MODULE_V1,
    &ngx_http_ceibacool_module_ctx, /* module context */
    ngx_http_ceibacool_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING};


static const ngx_str_t HELLO_WORD_LITERAL = ngx_string("hello, world");
static const ngx_str_t SET_COOKIE_LITERAL = ngx_string("Set-Cookie");
static const ngx_str_t LOCATION_LITERAL = ngx_string("Location");
static const ngx_str_t CEIBA_URL_LITERAL =
    ngx_string("https://ceiba.ntu.edu.tw/ChkSessLib.php");
static const ngx_str_t COOL_URL_LITERAL =
    ngx_string("https://cool.ntu.edu.tw/");


static ngx_int_t
ngx_http_ceibacool_handler(ngx_http_request_t *r)
{
    ngx_array_t *cookie_list;
    ngx_str_t *cookie_list_elems;

    ngx_table_elt_t *h;
    ngx_buf_t *b;
    ngx_int_t rc;
    ngx_chain_t out;
    ngx_http_ceibacool_loc_conf_t *mlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ceibacool handler");

    /* ignore client request body if any */

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_ceibacool_module);

    // login and get cookie

    if (mlcf->site == SITE_CEIBA)
        cookie_list = login_ceiba(r->pool, r->connection->log);
    else
        cookie_list = login_cool(r->pool, r->connection->log);

    if (!cookie_list) {
        log_err(r->connection->log, "get cookie_list");
        return NGX_ERROR;
    }
    cookie_list_elems = cookie_list->elts;

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

    // redirect location
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key = LOCATION_LITERAL;

    if (mlcf->site == SITE_CEIBA)
        h->value = CEIBA_URL_LITERAL;
    else
        h->value = COOL_URL_LITERAL;

    r->headers_out.status = NGX_HTTP_SEE_OTHER;
    r->headers_out.content_length_n = HELLO_WORD_LITERAL.len;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // send body

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = HELLO_WORD_LITERAL.data;
    b->last = HELLO_WORD_LITERAL.data + HELLO_WORD_LITERAL.len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_ceibacool_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ceibacool_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ceibacool_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->entries = NULL;
     */

    return conf;
}


static char *
ngx_http_ceibacool_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ceibacool_loc_conf_t *prev = parent;
    ngx_http_ceibacool_loc_conf_t *conf = child;

    if (conf->site == SITE_UNDEFINED) {
        conf->site = prev->site;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ceibacool_command_callback(ngx_conf_t *cf,
                                    ngx_command_t *cmd,
                                    void *conf)
{
    // Read command argument

    ngx_http_ceibacool_loc_conf_t *mlcf = conf;

    ngx_str_t *args = cf->args->elts;

    if (ngx_strncasecmp(args[1].data, (u_char *) "ceiba", 6) == 0) {
        mlcf->site = SITE_CEIBA;
    } else if (ngx_strncasecmp(args[1].data, (u_char *) "cool", 5) == 0) {
        mlcf->site = SITE_COOL;
    } else {
        log_err(cf->log, "unrecognized site for login");
        return NGX_CONF_ERROR;
    }

    // Set handler

    ngx_http_core_loc_conf_t *clcf =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_ceibacool_handler;

    ngx_log_stderr(0, "cf->log->level=%d\n", cf->log->log_level);

    return NGX_CONF_OK;
}
