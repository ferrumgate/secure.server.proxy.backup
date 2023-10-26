#!/bin/bash
mkdir -p /tmp/pac
cat <<EOF >/tmp/pac/pac.js
function FindProxyForURL(url, host) {
 
// If the hostname matches, send direct.
//    if (dnsDomainIs(host, "intranet.domain.com") ||
//        shExpMatch(host, "(*.abcdomain.com|abcdomain.com)"))
//        return "DIRECT";
 
// If the protocol or URL matches, send direct.
//    if (url.substring(0, 4)=="ftp:" ||
//        shExpMatch(url, "http://abcdomain.com/folder/*"))
//        return "DIRECT";
 
// If the requested website is hosted within the internal network, send direct.
//   if (isPlainHostName(host) ||
//        shExpMatch(host, "*.local") ||
//        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
//        isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0") ||
//        isInNet(dnsResolve(host), "192.168.0.0",  "255.255.0.0") ||
//        isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
//        return "DIRECT";
 
// If the IP address of the local machine is within a defined
// subnet, send to a specific proxy.
//    if (isInNet(myIpAddress(), "10.10.5.0", "255.255.255.0"))
//        return "PROXY 1.2.3.4:8080";
 
// DEFAULT RULE: All other traffic, use below proxies, in fail-over order.
//    return "PROXY 10.0.1.39:8081; PROXY 7.8.9.10:8080; DIRECT";
if(
    isInNet(host, "192.168.88.0",  "255.255.255.0"))
    return "DIRECT";
if(
    shExpMatch(host,"ferrumgate.com") ||
    shExpMatch(host,"*.ferrumgate.com")||
    shExpMatch(host,"*.ferrumgate.dev"))
    //return "QUIC try.ferrumgate.com:8443";
    return "HTTPS try.ferrumgate.com:8443";

return "HTTPS try.ferrumgate.com:8443";;
 
}

EOF

cp /tmp/pac/pac.js ./docker_ssl/nginx_data/
cd docker_ssl
bash run.sh
#docker stop pacjs-nginx || true
#docker rm packjs-nginx || true
#docker run -d --rm --name pacjs-nginx -v /tmp/pac:/usr/share/nginx/html:ro -p 8181:80 nginx
