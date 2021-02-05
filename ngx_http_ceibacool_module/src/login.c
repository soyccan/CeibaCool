#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <curl/curl.h>

#include "login.h"
#include "utils.h"


static int
_load_credentials(ngx_log_t *log,
                  u_char *username_path,
                  u_char *password_path,
                  u_char *username,
                  u_char *password,
                  size_t maxlen)
{
    // read credentials from file

    ngx_fd_t fd;
    ssize_t sz;

    fd = ngx_open_file(username_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd < 0) {
        log_err(log, "open file");
        return fd;
    }
    sz = ngx_read_fd(fd, username, maxlen - 1);
    if (sz < 0) {
        log_err(log, "read");
        return sz;
    }
    ngx_close_file(fd);
    while (sz && username[sz-1] == '\n') sz--;
    username[sz] = '\0';

    fd = ngx_open_file(password_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd < 0) {
        log_err(log, "open file");
        return fd;
    }
    sz = ngx_read_fd(fd, password, maxlen - 1);
    if (sz < 0) {
        log_err(log, "read");
        return sz;
    }
    ngx_close_file(fd);
    while (sz && password[sz-1] == '\n') sz--;
    password[sz] = '\0';

    log_debug(log, "load credentials: username=%s; password=%s", username, password);

    return 0;
}

// Login CEIBA and save the session cookie to COOKIEJAR_PATH
static int
_login_ceiba(ngx_pool_t *pool,
             ngx_log_t *log,
             u_char *username_path,
             u_char *password_path,
             u_char *cookiejar_path)
{
    CURL *curl;
    CURLcode res;

    ///////
    log_info(log, "Get Session from CEIBA Login Page");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        goto err;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://ceiba.ntu.edu.tw/ChkSessLib.php");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "get ceiba:%s", curl_easy_strerror(res));
        goto err;
    }
    curl_easy_cleanup(curl);


    ///////
    log_info(log, "Post Login Info");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        goto err;
    }

    u_char username[20], password[20], postfields[100];

    if (_load_credentials(log, username_path, password_path, username, password,
                          sizeof(username)) < 0) {
        log_err(log, "load credential");
        goto err;
    }

    u_char *postfields_end =
        ngx_snprintf(postfields, sizeof(postfields) - 1, "user=%s&pass=%s",
                     username, password);
    *postfields_end = '\0';

    if (postfields_end == postfields + sizeof(postfields) - 1) {
        log_err(log, "post field overflow");
        goto err;
    }
    log_debug(log, "post fields: %s", postfields);

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://web2.cc.ntu.edu.tw/p/s/login2/p1.php");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "login ceiba:%s", curl_easy_strerror(res));
        goto err;
    }
    curl_easy_cleanup(curl);

    return 0;

err:
    curl_easy_cleanup(curl);
    return -1;
}


typedef struct {
    ngx_pool_t *pool;
    ngx_log_t *log;
    u_char *str;
    size_t len;
} _saml_response_t;


static size_t
_search_saml_response(u_char *data,
                      size_t size,
                      size_t nmemb,
                      _saml_response_t *userdata)
{
    ngx_pool_t *pool = userdata->pool;
    ngx_log_t *log = userdata->log;

    if (size != 1) {
        log_err(log, "size");
        return 0;
    }

    size_t data_len = ngx_strnlen(data, CURL_MAX_WRITE_SIZE);
    u_char *match;

    match = ngx_strnstr(data, "SAMLResponse", data_len);
    if (!match)
        return 0;

    while (*match != '<' && match > data)
        match--;

    match = ngx_strnstr(match, "value=\"", data_len - (match - data));
    if (!match)
        return 0;

    match += 7;

    // TODO: set larger
    size_t dest_sz = 16;
    u_char *dest_begin = ngx_palloc(pool, dest_sz);
    if (!dest_begin) {
        log_err(log, "alloc");
        return 0;
    }
    u_char *dest = dest_begin;

    // field name
    memcpy(dest, "SAMLResponse=", 13);
    dest += 13;

    u_char *src = match;
    size_t n = nmemb - (src - data);
    while (*src && *src != '"' && n--) {
        if (dest_sz - (dest - dest_begin) < 3) {
            log_debug(log, "realloc, prev size=%lu", dest_sz);

            u_char *new_dest_begin = ngx_palloc(pool, dest_sz * 2);
            if (!new_dest_begin) {
                log_err(log, "alloc");
                ngx_pfree(pool, dest_begin);
                return 0;
            }
            memcpy(new_dest_begin, dest_begin, dest_sz);
            ngx_pfree(pool, dest_begin);
            dest_sz *= 2;

            dest = new_dest_begin + (dest - dest_begin);
            dest_begin = new_dest_begin;
        }

        if (*src == '+') {
            src++;
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = 'B';
        } else if (*src == '/') {
            src++;
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = 'F';
        } else if (*src == '=') {
            src++;
            *dest++ = '%';
            *dest++ = '3';
            *dest++ = 'D';
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';

    userdata->str = dest_begin;
    userdata->len = dest - dest_begin;

    return nmemb;
}

static int
_login_cool(ngx_pool_t *pool,
            ngx_log_t *log,
            u_char *username_path,
            u_char *password_path,
            u_char *cookiejar_path)
{
    CURL *curl;
    CURLcode res;
    u_char username[16], password[16];
    u_char login_url[2048];
    u_char *login_url_ptr;
    u_char postfields[512];
    u_char *postfields_end;
    _saml_response_t saml_response;

    ///////
    log_info(log, "Get Session from COOL Login Page");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        goto err;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, "https://cool.ntu.edu.tw/login/saml");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "get cool: %s", curl_easy_strerror(res));
        goto err;
    }

    login_url_ptr = NULL;
    res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &login_url_ptr);
    if (res == CURLE_OK && login_url_ptr) {
        /* This is the new absolute URL that you could redirect to, even if
         * the Location: response header may have been a relative URL. */
        u_char *login_url_end = ngx_cpystrn(login_url, login_url_ptr, sizeof(login_url));

        if (login_url_end == login_url + sizeof(login_url) - 1) {
            log_err(log, "login url overflow");
            goto err;
        }

        log_debug(log, "Redirected to: (%lu) %s", login_url_end - login_url, login_url);

    } else {
        log_err(log, "get redirect url");
        goto err;
    }
    curl_easy_cleanup(curl);


    ///////
    log_info(log, "Post Login Info");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        goto err;
    }

    if (_load_credentials(log, username_path, password_path, username, password,
                          sizeof(username)) < 0) {
        log_err(log, "load credential");
        goto err;
    }

    postfields_end =
        ngx_snprintf(postfields, sizeof(postfields) - 1,
                     "__VIEWSTATE=%%2FwEPDwUKMTY2MTc3NjUzM2RkUK4S8IU%%"
                     "2FlZeKUDrQIAtt4tRhRV4ZOkEMNdoJavm%%2FSBs="
                     "&__VIEWSTATEGENERATOR=0EE29E36"
                     "&__EVENTVALIDATION=%%2FwEdAAUdVdOEjcCKz7S6sLphMAmFlt%%"
                     "2FS8mKmQpmuxn2LW6B9thvLC%%"
                     "2FFQOf5u4GfePSXQdrRBPkcB0cPQF9vyGTuIFWmijKZWG4rH59f66Vc64"
                     "WGnN%%2FHmf00Q2eMalQURbQ6cPb45rGUVCHnIwpyxWjkkPDce"
                     "&__db=15"
                     "&ctl00%%24ContentPlaceHolder1%%24UsernameTextBox=%s"
                     "&ctl00%%24ContentPlaceHolder1%%24PasswordTextBox=%s"
                     "&ctl00%%24ContentPlaceHolder1%%24SubmitButton="
                     "%%E7%%99%%BB%%E5%%85%%A5",  // (UTF-8) "登入"
                     username, password);
    *postfields_end = '\0';
    log_debug(log, "postfield size = %lu", postfields_end - postfields);
    log_debug(log, "postfields: %s", postfields);

    if (postfields_end == postfields + sizeof(postfields) - 1) {
        log_err(log, "post field overflow");
        goto err;
    }

    saml_response.pool = pool;
    saml_response.log = log;

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, login_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _search_saml_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &saml_response);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postfields_end - postfields);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "login cool: %s", curl_easy_strerror(res));
        goto err;
    }

    log_debug(log, "SAMLResponse: %s", saml_response.str);

    curl_easy_cleanup(curl);


    ///////
    log_info(log, "Get COOL Homepage with Authenticated Session");
    curl = curl_easy_init();
    if (!curl) {
        log_err(log, "curl_easy_init");
        goto err;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, "https://cool.ntu.edu.tw/login/saml");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, saml_response.str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, saml_response.len);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "access cool: %s", curl_easy_strerror(res));
        goto err;
    }
    curl_easy_cleanup(curl);
    ngx_pfree(pool, saml_response.str);

    return 0;

err:
    curl_easy_cleanup(curl);
    return -1;
}

static ngx_array_t *
_parse_cookie_jar(ngx_pool_t *pool,
                  ngx_log_t *log,
                  u_char *path,
                  u_char *from_domain)
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

        // log_debug(log, "parsing cookiejar");
        // log_debug(log, "rd=%d wr=%d ch=%c state=%d", rd, wr, ch, state);
        // log_debug(log, "data=%s", data);
        // log_debug(log, "");

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
                    ngx_snprintf(http_form, sizeof(http_form) - 1, "%s=%s",
                                 guard_strptr(name), guard_strptr(value));
                *http_form_end = '\0';
                size_t http_form_len = http_form_end - http_form;

                size_t from_domain_len = ngx_strlen(from_domain);
                int match = ngx_strncasecmp(
                                domain, from_domain,
                                ngx_min(domain_len, from_domain_len) + 1) == 0;
                int match_sub =
                    ngx_strncasecmp(
                        domain + 1, from_domain,
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
    int res;

    res = _login_ceiba(pool, log, (u_char *) USERNAME_FILE,
                       (u_char *) PASSWORD_FILE, (u_char *) COOKIEJAR_PATH);

    if (res < 0)
        return NULL;

    return _parse_cookie_jar(pool, log, (u_char *) COOKIEJAR_PATH,
                             (u_char *) "ceiba.ntu.edu.tw");
}

ngx_array_t *
login_cool(ngx_pool_t *pool, ngx_log_t *log)
{
    int res;

    res = _login_cool(pool, log, (u_char *) USERNAME_FILE,
                      (u_char *) PASSWORD_FILE, (u_char *) COOKIEJAR_PATH);

    if (res < 0)
        return NULL;

    return _parse_cookie_jar(pool, log, (u_char *) COOKIEJAR_PATH,
                             (u_char *) "cool.ntu.edu.tw");
}