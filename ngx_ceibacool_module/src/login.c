#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include <curl/curl.h>

#include "login.h"
#include "utils.h"


// Login CEIBA and save the session cookie to COOKIEJAR_PATH
static int
_login_ceiba(ngx_pool_t *pool,
             ngx_log_t *log,
             const char *username_path,
             const char *password_path,
             const char *cookiejar_path)
{
    CURL *curl;
    CURLcode res;

    ///////
    log_info(log, "Get Session from CEIBA Login Page");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        return -1;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://ceiba.ntu.edu.tw/ChkSessLib.php");
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        log_err(log, "get ceiba:%s", curl_easy_strerror(res));
        return -1;
    }


    ///////
    log_info(log, "Post Login Info");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        return -1;
    }

    // read credentials from file

    u_char username[20], password[20], postfields[100];
    ngx_fd_t fd;
    ssize_t sz;

    fd = ngx_open_file(username_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd < 0) {
        log_err(log, "open file");
        return fd;
    }
    sz = ngx_read_fd(fd, username, sizeof(username) - 1);
    if (sz < 0) {
        log_err(log, "read");
        return sz;
    }
    ngx_close_file(fd);
    username[sz] = '\0';

    fd = ngx_open_file(password_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd < 0) {
        log_err(log, "open file");
        return fd;
    }
    sz = ngx_read_fd(fd, password, sizeof(password) - 1);
    if (sz < 0) {
        log_err(log, "read");
        return sz;
    }
    ngx_close_file(fd);
    password[sz] = '\0';

    u_char *postfields_end =
        ngx_snprintf(postfields, sizeof(postfields) - 1, "user=%s&pass=%s",
                     username, password);
    if (!postfields_end) {
        log_err(log, "snprintf");
        return -1;
    }
    *postfields_end = '\0';

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://web2.cc.ntu.edu.tw/p/s/login2/p1.php");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        log_err(log, "login ceiba:%s", curl_easy_strerror(res));
        return -1;
    }


    ///////
    log_info(log, "Get CEIBA Homepage with Authenticated Session");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        return -1;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://ceiba.ntu.edu.tw/ChkSessLib.php");
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        log_err(log, "access ceiba:%s", curl_easy_strerror(res));
        return -1;
    }

    return 0;
}

static ngx_array_t *
_parse_cookie_jar(ngx_pool_t *pool,
                  ngx_log_t *log,
                  const char *path,
                  const char *from_domain)
{
    ngx_fd_t cookiejar = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (cookiejar < 0) {
        log_err(log, "open cookie jar");
        return NULL;
    }

    ngx_array_t *cookie_list = ngx_array_create(pool, 4, sizeof(ngx_str_t));
    if (!cookie_list) {
        log_err(log, "allocate cookie list");
        return NULL;
    }

    u_char buf[16];

    u_char data[1024];
    size_t data_len = 0;

    enum { S_NEWLINE, S_DATA } state = S_NEWLINE;
    int is_eof = 0;

    for (ssize_t rd = sizeof(buf), wr = sizeof(buf); !is_eof; rd++) {
        if (rd == wr && wr == sizeof(buf)) {
            rd = 0;
            wr = ngx_read_fd(cookiejar, buf, sizeof(buf));
            // wr < sizeof(buf) indicates EOF

            if (wr < 0) {
                log_err(log, "read");
                break;
            }
        }

        is_eof = rd == wr && wr != sizeof(buf);

        // in case file is not newline-terminated
        u_char ch = is_eof ? '\n' : buf[rd];

        log_debug(log, "parsing cookiejar");
        log_debug(log, "rd=%d wr=%d ch=%c state=%d", rd, wr, ch, state);
        log_debug(log, "data=%s", data);
        log_debug(log, "");

        if (state == S_DATA) {
            if (ch == '\n') {
                state = S_NEWLINE;

                data[data_len] = '\0';
                data_len = 0;
                u_char *toparse = data;

                if (ngx_strncasecmp(data, (u_char *) "#httponly_", 10) == 0) {
                    // Ignore HttpOnly tag
                    toparse = data + 10;
                    log_debug(log, "ignore httponly data=%16s", data);
                } else if (data[0] == '#') {
                    // Ignore comment
                    log_debug(log, "ignore comment data=%16s", data);
                    continue;
                }

                // Parse
                u_char *domain = _ngx_strsep(&toparse, "\t\n");
                size_t domain_len = toparse - domain - 1;
                u_char *include_subdomain UNUSED =
                    _ngx_strsep(&toparse, "\t\n");
                u_char *path UNUSED = _ngx_strsep(&toparse, "\t\n");
                u_char *secure UNUSED = _ngx_strsep(&toparse, "\t\n");
                u_char *expires UNUSED = _ngx_strsep(&toparse, "\t\n");
                u_char *name = _ngx_strsep(&toparse, "\t\n");
                u_char *value = _ngx_strsep(&toparse, "\t\n");

                u_char http_form[1024];
                u_char *http_form_end =
                    ngx_snprintf(http_form, sizeof(http_form), "%s=%s",
                                 guard_strptr(name), guard_strptr(value));
                if (http_form_end == http_form + sizeof(http_form))
                    http_form_end--;
                *http_form_end = '\0';
                size_t http_form_len = http_form_end - http_form;

                size_t from_domain_len = ngx_strlen(from_domain);
                int match = ngx_strncasecmp(
                                domain, (u_char *) from_domain,
                                ngx_min(domain_len, from_domain_len) + 1) == 0;
                int match_sub =
                    ngx_strncasecmp(
                        domain + 1, (u_char *) from_domain,
                        ngx_min(domain_len - 1, from_domain_len) + 1) ==
                    0;  // match subdomain like: .ceiba.ntu.edu.tw
                if (!match && !match_sub) {
                    // ignore if cookie domain don't match from_domain
                    log_debug(log,
                              "http form ignored, domain=(%d)%s, "
                              "from_domain=(%d)%s: (%d)%s",
                              domain_len, domain, from_domain_len, from_domain,
                              http_form_len, http_form);
                    continue;
                }
                log_debug(log, "http form (%d): %s", http_form_len, http_form);

                ngx_str_t *cookie = ngx_array_push(cookie_list);
                if (!cookie) {
                    log_err(log, "push cookie");
                    continue;
                }

                cookie->len = http_form_len;
                cookie->data = ngx_pcalloc(pool, http_form_len + 1);
                if (!cookie->data) {
                    log_err(log, "alloc cookie data");
                    continue;
                }
                ngx_memcpy(cookie->data, http_form, http_form_len + 1);

            } else {  // ch != LF
                state = S_DATA;
                data[data_len++] = ch;
                if (data_len == sizeof(data)) {
                    log_err(log, "data overflow");
                    data_len = 0;
                }
            }

        } else if (state == S_NEWLINE) {
            if (ch == '\n') {
                state = S_NEWLINE;
            } else {
                state = S_DATA;
                data[data_len++] = ch;
                if (data_len == sizeof(data)) {
                    log_err(log, "data overflow");
                    data_len = 0;
                }
            }
        }
    }
    return cookie_list;
}


#define USERNAME_FILE "/home/nginx/username"
#define PASSWORD_FILE "/home/nginx/password"
#define COOKIEJAR_PATH "/home/nginx/cookies"


ngx_array_t *
login_ceiba(ngx_pool_t *pool, ngx_log_t *log)
{
    _login_ceiba(pool, log, USERNAME_FILE, PASSWORD_FILE, COOKIEJAR_PATH);

    return _parse_cookie_jar(pool, log, COOKIEJAR_PATH, "ceiba.ntu.edu.tw");
}

ngx_array_t *
login_cool(ngx_pool_t *pool, ngx_log_t *log)
{
    _login_cool(pool, log, USERNAME_FILE, PASSWORD_FILE, COOKIEJAR_PATH);

    return _parse_cookie_jar(pool, log, COOKIEJAR_PATH, "cool.ntu.edu.tw");
}