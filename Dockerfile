FROM ubuntu:20.04

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y install --no-install-recommends \
      tcpd \
      xinetd \
      gcc \
      libc6-dev \
  && apt-get clean && \
  rm -rf /var/lib/apt/lists/

# Switch from 'connections per second' rate limiting, since it disables the
# service completely (potential DoS) to 'maximum instances of service per
# source IP address' limit. The limit is the same default as for 'cps' (50).
RUN \
  sed -i 's/^}$/cps = 0 0\nper_source = 50\n}/' /etc/xinetd.conf && \
  grep "cps = 0" /etc/xinetd.conf && \
  grep "per_source = 50" /etc/xinetd.conf && \
  nl /etc/xinetd.conf

RUN mkdir /honeypot/
COPY ./smtp_bigturnip.c /honeypot/smtp_bigturnip.c
COPY ./honeypot_bigturnip /etc/xinetd.d/
WORKDIR /honeypot

RUN gcc -Wall -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -fstack-protector -o smtp_bigturnip smtp_bigturnip.c

ENTRYPOINT [ "xinetd", "-dontfork" ]