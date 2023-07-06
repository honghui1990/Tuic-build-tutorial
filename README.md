# **Installation**
```
apt update && apt -y install curl
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/NaiveProxy-installation/main/Install.sh)
```

# [Tuic](https://github.com/EAimTY/tuic)
- **Install the Tuic program**
```
apt -y update && apt -y install wget socat uuid-runtime && wget -O /usr/local/bin/tuic https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu && chmod +x /usr/local/bin/tuic
```
- **Download configuration file**
```
wget -O /usr/local/etc/config.json https://raw.githubusercontent.com/TinrLin/Tuic-build-tutorial/main/server.json && wget -P /etc/systemd/system https://raw.githubusercontent.com/TinrLin/Tuic-build-tutorial/main/tuic.service
```

- **Configure certificate**

 1.install acme

```
curl https://get.acme.sh | sh 
```
 2.set acme alias
```
alias acme.sh=~/.acme.sh/acme.sh
```
 3.auto update acme
```
acme.sh --upgrade --auto-upgrade
```
 4.Set acme's default CA
```
acme.sh --set-default-ca --server letsencrypt
```
 5.generate certificate(Replace www.example.com with your domain name）
```
acme.sh --issue -d www.example.com --standalone -k ec-256 --webroot /home/wwwroot/html
```
 6.install certificate(Replace www.example.com with your domain name）
```
acme.sh --install-cert -d www.example.com --ecc --key-file /etc/ssl/private/private.key --fullchain-file /etc/ssl/private/cert.crt
```

- **Modify the configuration file**

 Generate UUID
```
uuidgen
```
 Generate password
```
openssl rand -base64 32
```
- **View Tuic running status**

```
systemctl daemon-reload && systemctl enable --now tuic.service && systemctl status tuic.service
```
- **Download the Tuic kernel**

 [Tuic kernel](https://github.com/EAimTY/tuic/releases/download/tuic-client-1.0.0/tuic-client-1.0.0-x86_64-pc-windows-gnu.exe) 


