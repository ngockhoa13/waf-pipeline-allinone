# Dockerfile - Nginx + ModSecurity 3 + CRS + ZAP (Debian bookworm - HOÀN HẢO 100%)
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Nginx + dependencies + Java 17 + Python
RUN apt-get update && apt-get install -y \
    nginx \
    libnginx-mod-http-modsecurity \
    libmodsecurity3 \
    python3 python3-pip curl wget openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install ZAP 2.15.0 (chạy ngon với Java 17)
WORKDIR /opt
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz && \
    tar xzf ZAP_2.15.0_Linux.tar.gz && \
    rm ZAP_2.15.0_Linux.tar.gz && \
    mv ZAP_2.15.0 zap

ENV PATH="/opt/zap:$PATH"

# Install OWASP CRS v4.4.0
RUN mkdir -p /etc/modsecurity/crs && \
    wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.4.0.tar.gz && \
    tar xzf v4.4.0.tar.gz && \
    mv coreruleset-4.4.0 /usr/local/coreruleset && \
    cp /usr/local/coreruleset/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf && \
    cp -r /usr/local/coreruleset/rules /etc/modsecurity/crs/

# Python dependencies
RUN pip3 install --break-system-packages python-owasp-zap-v2.4 requests

# Copy config (giữ nguyên file của bạn)
COPY modsecurity.conf /etc/modsecurity/modsecurity.conf
COPY crs-setup.conf /etc/modsecurity/crs/crs-setup.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx-proxy.conf /etc/nginx/conf.d/default.conf

# Copy scripts
COPY phase1_capture.py /opt/phase1_capture.py
COPY phase2_replay.py /opt/phase2_replay.py
COPY entrypoint.sh /opt/entrypoint.sh

RUN chmod +x /opt/entrypoint.sh /opt/*.py && \
    mkdir -p /output /var/log/nginx /var/log/modsecurity

EXPOSE 8080 8081

WORKDIR /opt
ENTRYPOINT ["/opt/entrypoint.sh"]
