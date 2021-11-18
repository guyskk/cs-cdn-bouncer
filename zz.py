import requests

sess = requests.Session()
sess.headers["Fastly-Key"] = "Qm5PyEPo_Xfr01dB2piJAunwVnL1tSDq"

body = {
    "service_id": "FASTLY_SERVICE_ID",
    "version": "13",
    "name": "apply_acl",
    "priority": "100",
    "dynamic": "1",
    "type": "recv",
    "content": "if ((client.ip ~ testy) && !req.http.Fastly-FF){ error 403; }",
}
resp = sess.post(
    "https://api.fastly.com/service/7UrfKbhJLi7JC8NktS71OS/version/13/snippet", data=body
)
print(resp.json())
