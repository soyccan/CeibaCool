#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define log_general(level, fmt, ...) \
    fprintf(stderr, "[\e[31m" level "\e[0m] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define log_info(log, fmt, ...) \
    log_general("info", fmt, ##__VA_ARGS__)
#define log_debug(log, fmt, ...) \
    log_general("debug", fmt, ##__VA_ARGS__)
#define log_err(log, fmt, ...) \
    log_general("error", fmt, ##__VA_ARGS__)


static size_t
_search_saml_response(char *data, 
                      size_t size, 
                      size_t nmemb, 
                      char **userdata)
{
    if (size != 1) {
        log_err(log, "size");
        return 0;
    }

    size_t body_len = strnlen(data, CURL_MAX_WRITE_SIZE);
    const char *match;

    match = strnstr(data, "SAMLResponse", body_len);
    if (!match)
        return 0;

    while (*match != '<' && match > data)
        match--;

    match = strnstr(match, "value=\"", body_len - (match - data));
    if (!match)
        return 0;

    match += 7;
    
    // TODO: set larger
    size_t dest_sz = 16;
    char *dest_begin = malloc(dest_sz);
    if (!dest_begin) {
        log_err(log, "alloc");
        return 0;
    }
    char *dest = dest_begin;

    // field name
    memcpy(dest, "SAMLResponse=", 13);
    dest += 13;

    const char* src = match;
    size_t n = nmemb - (src - data);
    while (*src && *src != '"' && n--) {
        if (dest_sz - (dest - dest_begin) < 3) {
            log_debug(log, "realloc, prev size=%lu", dest_sz);

            char *new_dest_begin = realloc(dest_begin, dest_sz *= 2);
            if (!new_dest_begin) {
                log_err(log, "alloc");
                free(dest_begin);
                return 0;
            }

            dest = new_dest_begin + (dest - dest_begin);
            dest_begin = new_dest_begin;
        }

        if (*src == '+') {
            src++;
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = 'B';
        }
        else if (*src == '=') {
            src++;
            *dest++ = '%';
            *dest++ = '3';
            *dest++ = 'D';
        }
        else { // include '/'
            *dest++ = *src++;
        }
    }
    *dest = '\0';

    *userdata = dest_begin;

    return nmemb;
}

int
main()
{
    const char *cookiejar_path = "cookies";

    CURL *curl;
    CURLcode res;
    char *login_url;
    char *saml_response;
    char postfields[500];


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
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "get cool: %s", curl_easy_strerror(res));
        goto err;
    }

    login_url = NULL;
    res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &login_url);
    if (res == CURLE_OK && login_url) {
        /* This is the new absolute URL that you could redirect to, even if
         * the Location: response header may have been a relative URL. */
        log_debug(log, "Redirected to: %s", login_url);
    }
    else {
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

    const char username[] = "b07902143";
    const char password[] = "ntuS2143";
    size_t sz = snprintf(postfields, sizeof(postfields) - 1,
        "__VIEWSTATE=/wEPDwUKMTY2MTc3NjUzM2RkUK4S8IU/lZeKUDrQIAtt4tRhRV4ZOkEMNdoJavm/SBs="
        "&__VIEWSTATEGENERATOR=0EE29E36"
        "&__EVENTVALIDATION=/wEdAAUdVdOEjcCKz7S6sLphMAmFlt/S8mKmQpmuxn2LW6B9thvLC/FQOf5u4GfePSXQdrRBPkcB0cPQF9vyGTuIFWmijKZWG4rH59f66Vc64WGnN/Hmf00Q2eMalQURbQ6cPb45rGUVCHnIwpyxWjkkPDce"
        "&__db=15"
        "&ctl00$ContentPlaceHolder1$UsernameTextBox=%s"
        "&ctl00$ContentPlaceHolder1$PasswordTextBox=%s"
        "&ctl00$ContentPlaceHolder1$SubmitButton=\xe7\x99\xbb\xe5\x85\xa5",  // (UTF-8) "登入"
        username, password);
    log_debug(log, "sz = %d", sz);
    
    if (sz > sizeof(postfields) - 1) {
        log_err(log, "post field overflow");
        goto err;
    }

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, login_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _search_saml_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &saml_response);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "login cool: %s", curl_easy_strerror(res));
        goto err;
    }

    log_debug(log, "SAMLResponse: %s", saml_response);

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
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://cool.ntu.edu.tw/login/saml");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, saml_response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "access cool: %s", curl_easy_strerror(res));
        goto err;
    }
    curl_easy_cleanup(curl);

    return 0;

err:
    curl_easy_cleanup(curl);
    return -1;
}