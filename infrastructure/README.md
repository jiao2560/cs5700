# SRFT Networking Project - AWS Infrastructure

## Overview
This infrastructure provides 2 EC2 instances in AWS for testing the Secure Reliable File Transfer (SRFT) networking project. The instances are configured with:
- **2 × t3.micro instances** (Amazon Linux 2) in the same availability zone (us-east-1a)
- **Public IP addresses** for SSH access
- **Session Manager** for secure AWS console-based access
- **Security Group** allowing all traffic (0.0.0.0/0)
- **Project files** pre-installed and configured for network testing

## Prerequisites
1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed and configured (`aws configure`)
3. **SSH client** (OpenSSH) installed locally
4. **Terraform** (optional, only for infrastructure modifications)

## Instance Details

### Instance 1 (Server)
- **Instance ID**: `i-040e18f87c0486ea2`
- **Public IP**: `54.84.110.211`
- **Private IP**: `10.0.1.111`
- **Availability Zone**: `us-east-1a`
- **Role**: Server (listens on port 9999)

### Instance 2 (Client)
- **Instance ID**: `i-0c2a9d8ef52e3821e`
- **Public IP**: `34.225.198.56`
- **Private IP**: `10.0.1.44`
- **Availability Zone**: `us-east-1a`
- **Role**: Client (connects to server on port 8888)

## Connection Methods

### Method 1: SSH (Recommended)
**SSH Key Location**: `infrastructure/srft-networking-key.pem`

1. **Set correct permissions** (required for SSH):
   ```bash
   chmod 600 infrastructure/srft-networking-key.pem
   ```

2. **Connect to Instance 1 (Server)**:
   ```bash
   ssh -i infrastructure/srft-networking-key.pem ec2-user@54.84.110.211
   ```

3. **Connect to Instance 2 (Client)**:
   ```bash
   ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56
   ```

4. **Quick test commands**:
   ```bash
   # Test connection to Instance 1
   ssh -i infrastructure/srft-networking-key.pem ec2-user@54.84.110.211 "hostname && python3 --version"
   
   # Test connection to Instance 2
   ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56 "hostname && python3 --version"
   
   # Test network connectivity between instances
   ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56 "ping -c 3 10.0.1.111"
   ```

## Project Setup

### Files Location
- **Project directory**: `/home/ec2-user/cs5700/`
- **Configuration file**: `/home/ec2-user/cs5700/config.py`

### Configuration
The `config.py` file is already configured with the correct private IPs:
```python
SERVER_IP = "10.0.1.111"    # Instance 1 private IP
CLIENT_IP = "10.0.1.44"     # Instance 2 private IP

SERVER_PORT = 9999
CLIENT_PORT = 8888
```

### Dependencies
- **Python 3.7**: Pre-installed on Amazon Linux 2
- **Cryptography library**: Already installed via `pip3 install cryptography`

### Verify Setup
Run these commands to verify everything is working:

```bash
# On Instance 1 (Server)
ssh -i infrastructure/srft-networking-key.pem ec2-user@54.84.110.211 "cd /home/ec2-user/cs5700 && python3 -c 'import secure_transfer; print(\"Import successful\")'"

# On Instance 2 (Client)
ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56 "cd /home/ec2-user/cs5700 && python3 -c 'import secure_transfer; print(\"Import successful\")'"
```

## Testing the SRFT Application

### Step 1: Start the Server
On **Instance 1 (Server)**, run:
```bash
cd /home/ec2-user/cs5700
python3 secure_transfer.py
# Or use the appropriate entry point for your server implementation
```

### Step 2: Run the Client
On **Instance 2 (Client)**, run:
```bash
cd /home/ec2-user/cs5700
python3 secure_transfer.py
# Or use the appropriate entry point for your client implementation
```

### Step 3: Test Connectivity
1. **Basic network test**:
   ```bash
   # From client to server (should see 3 ping responses)
   ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56 "ping -c 3 10.0.1.111"
   ```

2. **Port connectivity test**:
   ```bash
   # Check if server port is listening (from client)
   ssh -i infrastructure/srft-networking-key.pem ec2-user@34.225.198.56 "nc -zv 10.0.1.111 9999"
   ```


### Project Testing Workflow
1. **SSH to both instances** (use separate terminal windows)
2. **Start server** on Instance 1
3. **Run client** on Instance 2
4. **Test file transfer** using private IPs (10.0.1.111 and 10.0.1.44)
5. **Monitor output** and debug as needed
