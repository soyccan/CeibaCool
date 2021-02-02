#ifndef _UTILS_H_
#define _UTILS_H_


#include <ngx_config.h>
#include <ngx_core.h>


#define UNUSED __attribute__((unused))


#define LOG_COLOR_BEGIN_red "\e[31m"
#define LOG_COLOR_BEGIN_green "\e[32m"
#define LOG_COLOR_BEGIN_yellow "\e[33m"
#define LOG_COLOR_BEGIN_blue "\e[34m"
#define LOG_COLOR_BEGIN_magenta "\e[35m"
#define LOG_COLOR_BEGIN_cyan "\e[36m"
#define LOG_COLOR_BEGIN_white "\e[37m"
#define LOG_COLOR_CLEAR "\e[0m"
#define LOG_COLOR(color, msg) LOG_COLOR_BEGIN_##color msg LOG_COLOR_CLEAR


#ifndef NDEBUG
#define log_debug(log, fmt, ...) \
    ngx_log_stderr(ngx_errno, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
// ngx_log_error(NGX_LOG_DEBUG, log, ngx_errno, "%s:%d: " fmt "\n", __FILE__,
//               __LINE__, ##__VA_ARGS__)
#else
#define log_debug(...)
#endif


#define log_err(log, fmt, ...)                                          \
    ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "%s:%d: " fmt, __FILE__, \
                  __LINE__, ##__VA_ARGS__)

#define log_info(log, fmt, ...)                                          \
    ngx_log_error(NGX_LOG_INFO, log, ngx_errno, "%s:%d: " fmt, __FILE__, \
                  __LINE__, ##__VA_ARGS__)


// log on system call error
#define log_on_err(expr) \
    if ((expr) < 0) {    \
        log_err(#expr);  \
    }

// return on system call error
#define ret_on_err(expr, ret_val) \
    if ((expr) < 0) {             \
        log_err(#expr);           \
        return ret_val;           \
    }

// return empty to string if string pointer is NULL
#define guard_strptr(str) ((str) ? (typeof(str))(str) : (typeof(str)) "")


// Require *stringp to be null-terminated string
UNUSED static u_char *
_ngx_strsep(u_char **stringp, const char *delim)
{
    u_char *token = *stringp;
    int done = 0;
    for (; !done && **stringp; (*stringp)++) {
        for (const char *c = delim; *c; c++) {
            if (**stringp == *c) {
                done = 1;
                **stringp = '\0';
                break;
            }
        }
    }
    return token;
}


#endif  // _UTILS_H_
