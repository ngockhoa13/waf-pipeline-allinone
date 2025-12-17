#!/bin/sh
set -e

echo "════════════════════════════════════════════════════"
echo " 🛡️  MODSECURITY + NGINX WAF"
echo "════════════════════════════════════════════════════"
echo " Target Domain: $TARGET_DOMAIN"
echo "════════════════════════════════════════════════════"

mkdir -p /output /var/log/nginx /var/log/modsecurity/audit

# Replace TARGET_DOMAIN in nginx config
sed -i "s/\${TARGET_DOMAIN}/$TARGET_DOMAIN/g" /etc/nginx/conf.d/proxy.conf

# Test configuration
echo "🔧 Testing Nginx configuration..."
nginx -t

# Start Nginx
echo "🚀 Starting Nginx + ModSecurity WAF..."
nginx -g "daemon off;" &

# Wait for port 8080
echo "⏳ Waiting for Nginx to listen on 8080..."
for i in $(seq 1 30); do
    if nc -z localhost 8080 2>/dev/null; then
        echo "✅ Nginx + ModSecurity ready on :8080"
        break
    fi
    sleep 1
done

# Keep container running
wait
