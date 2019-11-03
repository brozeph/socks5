# Socks5

Intended to be a Go port of the Node.js [simple-socks](https://github.com/brozeph/simple-socks) module.

## In Progress

## To run

```bash
go run main.go 1080
```

In a separate terminal window, to test the server:

```bash
# standard SOCKS5
curl https://google.com --socks5 127.0.0.1:1080
# hostname resolution at server
curl https://google.com --socks5-hostname 127.0.0.1:1080
# IPv6
curl https://google.com --socks5 127.0.0.1:1080 -6
```
