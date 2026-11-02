# Fixture: key generation in a Dockerfile (generic shell-command rules).
FROM alpine:3.20
RUN apk add --no-cache openssl openssh-keygen
RUN openssl genrsa -out /etc/ssl/server.key 2048 && \
    openssl req -new -x509 -sha1 -key /etc/ssl/server.key -out /etc/ssl/server.crt
RUN openssl dhparam -out /etc/nginx/dhparam.pem 4096
RUN ssh-keygen -t rsa -b 3072 -N "" -f /root/.ssh/id_rsa
RUN openssl genpkey -algorithm ed25519 -out /etc/ssl/ed.pem

# Near-misses:
RUN openssl version && ssh-keygen -l -f /etc/ssh/key.pub
RUN apk add openssl-dev
