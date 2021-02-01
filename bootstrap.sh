set -ex
cd /root/nginx-1.19.6
make -j 6
make install
cd /root
nginx -g 'daemon off;'