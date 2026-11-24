# Reusable investigation commands

Run relative PCAP commands from `~/captures`.

## Network scanning
```bash
tshark -r investigation.pcap -Y 'ip.src == 10.14.22.88 && ip.dst == 10.14.30.0/24 && tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.dst | sort -u | wc -l
```

## HTTP beaconing
```bash
tshark -r investigation.pcap -Y 'ip.src == 10.14.22.88 && ip.dst == 194.165.16.56 && http.request' -T fields -e http.request.uri | sort | uniq -c
```

## Base64 command
```bash
echo "d2hvYW1p" | base64 -d; echo
```

## Reverse shell and archive staging
```bash
tshark -r investigation.pcap -Y 'tcp contains "Compress-Archive"' -T fields -e frame.number -e tcp.stream
tshark -r investigation.pcap -q -z follow,tcp,ascii,112
```

## HTTP redirect
```bash
tshark -r investigation.pcap -Y 'http.response.code == 302' -T fields -e frame.time -e ip.src -e http.location
```

## Executable extraction
```bash
cd ~/extracted
file *
xxd -l 32 winservice-patch-4891.pdf
sha256sum winservice-patch-4891.pdf
```

## Archive extraction
```bash
cd ~/extracted
file upload
ls -lh upload
sha256sum upload
```

## Threat intelligence correlation
```bash
grep -i "4ec66c72e7d80620891118cb32206771ac37a227b6e77a2549b046748d8c234b" ~/references/threat_feed.txt
```

## TLS certificate
```bash
openssl x509 -inform DER -in ~/captures/c2_cert.der -noout -subject
```

## JA4 fingerprint
```bash
tshark -r investigation.pcap -Y 'ip.src == 10.14.22.88 && ip.dst == 194.165.16.56 && tls.handshake.type == 1' -T fields -e tls.handshake.ja4 | sort | uniq -c
```

## DNS tunnel hunting
```bash
tshark -r investigation.pcap -Y 'dns.flags.response == 0 && len(dns.qry.name) > 50' -T fields -e dns.qry.name | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' | sort | uniq -c | sort -nr
```

## Automated IoC extraction
```bash
bash ~/scripts/extract_iocs.sh
ls -lh ~/evidence/iocs/
wc -l ~/evidence/iocs/external_ips.txt
```
