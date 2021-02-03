set -ex
cd /root/nginx-1.19.6
make -j 6
make install
cd /home/nginx
nginx -g 'daemon off;'