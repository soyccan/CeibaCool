#include <curl/curl.h>
#include <stdio.h>

#define log_info(log, fmt, ...) \
    fprintf(stderr, "[\e[31minfo\e[0m]" fmt "\n", ##__VA_ARGS__)
#define log_debug(log, fmt, ...) \
    fprintf(stderr, "[\e[31mdebug\e[0m]" fmt "\n", ##__VA_ARGS__)
#define log_err(log, fmt, ...) \
    fprintf(stderr, "[\e[31merror\e[0m]" fmt "\n", ##__VA_ARGS__)

int
main()
{
    const char *cookiejar_path = "cookies";

    CURL *curl;
    CURLcode res;
    char *login_location;

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
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiejar_path);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "get cool: %s", curl_easy_strerror(res));
        goto err;
    }

    login_location = NULL;
    res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &login_location);
    if (res == CURLE_OK && login_location) {
        /* This is the new absolute URL that you could redirect to, even if
         * the Location: response header may have been a relative URL. */
        log_debug(log, "Redirected to: %s", login_location);
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

#ifndef NDEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, login_location);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                     "ctl00$ContentPlaceHolder1$UsernameTextBox=b07902143"
                     "&ctl00$ContentPlaceHolder1$PasswordTextBox=ntuS2143");

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err(log, "login cool: %s", curl_easy_strerror(res));
        goto err;
    }
    curl_easy_cleanup(curl);


    ///////
//     log_info(log, "Get CEIBA Homepage with Authenticated Session");
//     curl = curl_easy_init();
//     if (!curl) {
//         log_err(log, "curl_easy_init");
//         return -1;
//     }
//
// #ifndef NDEBUG
//     curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
// #endif
//     curl_easy_setopt(curl, CURLOPT_URL,
//                      "https://ceiba.ntu.edu.tw/ChkSessLib.php");
//     curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
//     curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
//     curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiejar_path);
//
//     res = curl_easy_perform(curl);
//     if (res != CURLE_OK) {
//         log_err(log, "acces ceiba:%s", curl_easy_strerror(res));
//     }
//     curl_easy_cleanup(curl);

    return 0;

err:
    curl_easy_cleanup(curl);
    return -1;
}