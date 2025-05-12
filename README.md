# **netmon**

A simple network monitoring tool for Linux.

`netmon` allows you to monitor network traffic, filter it based on PID (process ID), capture specific protocols (TCP/UDP), and save captured packets to a file. It's an easy-to-use solution for network diagnostics, useful for troubleshooting and performance monitoring.

## **Features**

* Monitor traffic on a specific network interface.
* Track network traffic related to a specific process using its PID.
* Filter network traffic by TCP or UDP protocol.
* Capture packets on specific ports.
* Log captured traffic to a file for later analysis.

## **Dependencies**

Ensure the following dependencies are installed before building the tool:

### For AlmaLinux (and other RHEL-based distributions):

```bash
sudo dnf install libpcap libpcap-devel
```

Additionally, the Go environment is required to build the tool:

* Go version 1.18 or later

## **Build Instructions**

To build the tool, follow these steps:

1. Clone the repository (if you haven’t already):

   ```bash
   git clone https://github.com/your-repo/netmon.git
   cd netmon
   ```

2. Build the project:

   ```bash
   go build -o netmon
   ```

3. You should now have the `netmon` executable in your directory.

## **Usage**

### Basic Usage

1. **Monitor all network traffic**:

   ```bash
   sudo ./netmon -iface eth0 -stats=true -trace=true -duration 15
   ```

2. **Monitor traffic related to a specific application (via PID)**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 1234
   ```

3. **Log captured traffic to a file**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094 -logfile capture.log
   ```

4. **Capture traffic for 10 seconds and log to `capture.log`**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094 -duration 10 -logfile capture.log
   ```

### Filtering by Protocol

5. **Capture all TCP traffic on port 80**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094 -protocol tcp -port 80
   ```

6. **Capture only UDP traffic**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094 -protocol udp
   ```

7. **Capture both TCP and UDP traffic (default behavior)**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094
   ```

8. **Capture all traffic (TCP or UDP) involving port 443**:

   ```bash
   sudo ./netmon -iface eth0 -trace -pid 946094 -port 443
   ```

### Command Flags

* `-iface`: Specify the network interface to monitor (e.g., `eth0`).
* `-stats`: Enable display of basic network stats from `/proc/net/dev`.
* `-trace`: Enable packet capture.
* `-pid`: Capture traffic related to a specific process ID (PID).
* `-duration`: Duration of the capture in seconds (default is 10 seconds).
* `-logfile`: Log captured packets to a file.
* `-protocol`: Filter traffic by protocol (`tcp`, `udp`, or `all`).
* `-port`: Filter traffic by port number.

## **Example Commands**

* **Monitor all traffic**:

  ```bash
  sudo ./netmon -iface eth0 -stats=true -trace=true -duration 15
  ```

* **Monitor specific application traffic (e.g., PID 1234)**:

  ```bash
  sudo ./netmon -iface eth0 -trace -pid 1234
  ```

* **Capture traffic and log it to `capture.log`**:

  ```bash
  sudo ./netmon -iface eth0 -trace -pid 946094 -logfile capture.log
  ```

* **Capture only TCP traffic on port 80**:

  ```bash
  sudo ./netmon -iface eth0 -trace -pid 946094 -protocol tcp -port 80
  ```

## **Troubleshooting**

* **Permission Issues**: Some features require root privileges, especially monitoring traffic and accessing `/proc` data. Always run the program with `sudo` where necessary.

* **Interface not found**: Make sure the interface (`-iface`) specified exists on your machine by running `ifconfig` or `ip a`.
