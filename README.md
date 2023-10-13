# SPAroid

Single Packet Authorization client library implementation in Go, only client library is implemented. SPA sends a single encrypted and HMACed UDP package to a server, the server upon receiving it verifies and decrypts it and then executes a command, most often opening the firewall for the client that sent the package. This allows you to employ a reject-all firewall but open the firewall for e.g. SSH access. It's a first line of defence, in the case of 0-day attacks on SSH or similar.

## Develop

`go mod tidy`
`go test`

### Using modd


Modd is a tool that continuesly monitors a set of files and runs commands on chagnes to those files. The configuration is done in `modd.conf`

You can install the development tool (https://github.com/cortesi/modd)[modd] by running

```
$ go install github.com/cortesi/modd/cmd/modd@latest
```

After that you should be able to execute the command:

``` 
modd
```
