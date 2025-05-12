# netmon
Simple network monitoring

### dependencies:

```
sudo dnf install libpcap libpcap-devel

```

To run the code:
```
# to monitor all traffic from the node
sudo ./netmon -iface eth0 -stats=true -trace=true -duration 15

# to monitor traffic from specific application (via its PID)
sudo ./netmon -iface eth0 -trace -pid 1234

# To capture traffic and log it to a file (capture.log):
sudo ./netmon -iface eth0 -trace -pid 946094 -logfile capture.log
# To capture traffic for 10 seconds and log to capture.log:
sudo ./netmon -iface eth0 -trace -pid 946094 -duration 10 -logfile capture.log

```
