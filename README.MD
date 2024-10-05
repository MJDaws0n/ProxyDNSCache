# What is it
Redirectes all TCP connections on port 80 to 443 and also all connections on port 443 to the respected domain, for example https://bob.com/ could go to localhost:304 

# Notice
Ip's for http connections are put on the headers as `X-Forwarded-For`, so you need to find a way to set the IP to that, you can with nginx easy

# Setup
if that was how you set it up, you set it up by adding an SRV record on your domain that looks like 	

_pdcache._tcp.test.com

replace test.com with your domain or subdomain, then set priority to 10, weight to 10, port to your port and target to the domain, it can be localhost if you want, but not an IP.

# Then edit config.yml to have all your certicate locations

# Make a service
To make a service that runs auto then do this

```sh
sudo nano /etc/systemd/system/ProxyDNSCache.service
```

paste this:
```systemd
[Unit]
Description=ProxyDNSCache
After=network.target

[Service]
ExecStart=/path/to/your/ProxyDNSCache
WorkingDirectory=/path/to/your/
Restart=always
User=your-username
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

Edit `your-username` to your username and edit the paths to the path of the executable, then change the `WorkingDirectory` to that same place the executable is in

```sh
sudo systemctl daemon-reload
sudo systemctl start ProxyDNSCache
sudo systemctl enable ProxyDNSCache
```

Your done