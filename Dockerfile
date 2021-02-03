## https://gist.github.com/hermanbanken/96f0ff298c162a522ddbba44cad31081
## Build Stage 1
FROM nginx:1.19.6-alpine AS builder

# nginx:alpine contains NGINX_VERSION environment variable, like so:
# ENV NGINX_VERSION 1.19.6

# For latest build deps, see:
# https://github.com/nginxinc/docker-nginx/blob/master/mainline/alpine/Dockerfile
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    linux-headers \
    libxslt-dev \
    gd-dev \
    geoip-dev \
    perl-dev \
    libedit-dev \
    mercurial \
    bash \
    alpine-sdk \
    findutils \
    curl-dev \
    gdb \
    easy-rsa

WORKDIR /root

# Prepare source and do some modification
# Colurful logging!
# Notice: this breaks config command "error_log /path/to/log/file notice;"
#         since the keyword "notice" (or emerg, alert, etc.) changes
RUN wget "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" && \
    tar -xf nginx-${NGINX_VERSION}.tar.gz && \
    sed -i -e 's/ngx_string("emerg")/ngx_string("\\e[31memerg\\e[0m")/g' \
           -e 's/ngx_string("alert")/ngx_string("\\e[31malert\\e[0m")/g' \
           -e 's/ngx_string("crit")/ngx_string("\\e[31mcrit\\e[0m")/g' \
           -e 's/ngx_string("error")/ngx_string("\\e[31merror\\e[0m")/g' \
           -e 's/ngx_string("warn")/ngx_string("\\e[33mwarn\\e[0m")/g' \
           -e 's/ngx_string("notice")/ngx_string("\\e[33mnotice\\e[0m")/g' \
           -e 's/ngx_string("info")/ngx_string("\\e[33minfo\\e[0m")/g' \
           nginx-${NGINX_VERSION}/src/core/ngx_log.c

# Configuration
COPY ngx_http_ceibacool_module/config ngx_http_ceibacool_module/config

# Reuse same cli arguments as nginx:alpine image used to build
# /root/ngx_ceibacool_module/src and /root/nginx-${NGINX_VERSION}/objs is bind-mounted
RUN export CONF_ARGS=$(nginx -V 2>&1 | sed -n -e 's/^.*arguments: //p') && \
    cd nginx-${NGINX_VERSION} && \
    # bash -c "./configure ${CONF_ARGS} --add-module=../ngx_ceibacool_module"
    sh -c "./configure ${CONF_ARGS} --with-debug --with-compat --add-dynamic-module=../ngx_http_ceibacool_module"

# Build
# RUN cd nginx-${NGINX_VERSION} && \
#     make -j6 && make install

# Generate certificate with exising CA certificate
COPY pki/ca.crt ca.crt
COPY pki/private/ca.key ca.key
RUN cp -r /usr/share/easy-rsa . && \
    cd easy-rsa && \
    sed -i "/\[ easyrsa_ca \]/a extendedKeyUsage = serverAuth" openssl-easyrsa.cnf && \
    ./easyrsa init-pki && \
    CA_OPTS='--batch \
             --dn-mode="org" \
             --req-c="TW" \
             --req-st="Taiwan" \
             --req-city="Tainan" \
             --req-org="SOYCCAN" \
             --req-email="mail@soyccan.tw" \
             --req-ou="Root CA" \
             --req-cn="SOYCCAN Root CA"' && \
    sh -c "./easyrsa ${CA_OPTS} build-ca nopass" && \
    cp /root/ca.crt pki/ca.crt && \
    cp /root/ca.key pki/private/ca.key && \
    CERT_OPTS='--batch \
               --dn-mode="org" \
               --req-c="TW" \
               --req-st="Taiwan" \
               --req-city="Tainan" \
               --req-org="SOYCCAN" \
               --req-email="mail@soyccan.tw" \
               --req-ou="Ceiba Cool" \
               --req-cn="ceibacool.soyccan.tw" \
               --subject-alt-name="DNS:ceiba.ntu.edu.tw, DNS:cool.ntu.edu.tw, DNS:ceibacool.soyccan.tw, IP:140.112.243.11" \
               --days="825"' && \
    sh -c "./easyrsa ${CERT_OPTS} gen-req ceibacool nopass" && \
    sh -c "./easyrsa ${CERT_OPTS} sign-req server ceibacool" && \
    cp pki/issued/ceibacool.crt /etc/ssl/ceibacool.crt && \
    cp pki/private/ceibacool.key /etc/ssl/private/ceibacool.key

# Merge dir tree
COPY ./nginx-conf/ /etc/nginx/
COPY ./html /usr/share/nginx/html

# NGINX workers are run as user "nginx", so they cannot access /root
RUN mkdir /home/nginx && \
    chown -R nginx:nginx /home/nginx

COPY --chown=nginx:nginx credentials/ /home/nginx/

STOPSIGNAL SIGTERM
STOPSIGNAL SIGINT

# For Development Stage, Incremental Build
COPY bootstrap.sh /
CMD ["bash", "/bootstrap.sh"]

# WORDDIR /home/nginx
# CMD ["nginx", "-g", "daemon off;"]




## Build Stage 2
# FROM nginx:1.19.6-alpine

# COPY --from=builder /usr/lib/nginx/modules/ngx_ceibacool_module.so /usr/lib/nginx/modules/ngx_ceibacool_module.so
