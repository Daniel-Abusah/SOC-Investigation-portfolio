# Indicators of compromise

| Type | Value | Context |
|---|---|---|
| Internal host | 10.14.22.88 | Investigated endpoint |
| External IP | 194.165.16.56 | HTTP beacons and TLS |
| External IP | 194.165.16.78 | Reverse shell port 4444 |
| External IP | 185.213.154.201 | HTTP archive POST |
| IP | 203.0.113.50 | Redirect source; documentation range |
| Domain | files.cdn-delivery.net | Redirect target |
| Certificate CN | update.softpatch-cdn.com | Subject claim |
| DNS suffix | exfil.fastsync-cdn.net | 40 long queries |
| URI | /api/v2/check | HTTP beacon |
| URI | /upload | Archive POST |
| Filename | winservice-patch-4891.pdf | Disguised executable |
| SHA256 | `4ec66c72e7d80620891118cb32206771ac37a227b6e77a2549b046748d8c234b` | Executable |
| SHA256 | `d17a83cf82a3cf4e5b3891e8b0923d00b22181e3079624cec60ca105c0eaf369` | Exported ZIP object |
| JA4 | `t13d040400_98dd3bb0ed34_34f36fd09b12` | Six Client Hellos |

Lab indicators only. Do not treat these as a current production blocklist. The full eight-IP list was not captured in the supplied screenshots.
