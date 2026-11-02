# Fixture: an nginx site file with no extension; old Mozilla "intermediate" style.
server {
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
}
