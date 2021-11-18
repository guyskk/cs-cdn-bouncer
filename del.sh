#!/bin/bash
for i in {0..101}
do
    curl -X "DELETE" -H "Fastly-Key: Qm5PyEPo_Xfr01dB2piJAunwVnL1tSDq" "https://api.fastly.com/service/4UPMVIYEaxIQRh0QaCcwkV/version/25/acl/crowdsec_$i" &
done