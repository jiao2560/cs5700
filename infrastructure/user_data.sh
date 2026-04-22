#!/bin/bash
# User data script for SRFT networking project instances

set -e

# Update system and install Python 3
echo "Updating system packages..."
sudo yum update -y

echo "Installing Python 3 and pip..."
sudo yum install -y python3 python3-pip

echo "Installing additional utilities..."
sudo yum install -y git wget curl net-tools

# Create project directory
PROJECT_DIR="/home/ec2-user/cs5700"
echo "Creating project directory at $PROJECT_DIR..."
sudo mkdir -p $PROJECT_DIR
sudo chown -R ec2-user:ec2-user $PROJECT_DIR

# Install Python dependencies (if requirements.txt exists in the future)
# echo "Installing Python dependencies..."
# pip3 install --user -r $PROJECT_DIR/requirements.txt

# Start and enable SSM agent (should already be running on Amazon Linux 2)
echo "Ensuring SSM agent is running..."
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

# Create a simple test script
cat > $PROJECT_DIR/test_connection.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys

def test_network():
    try:
        # Test basic socket creation
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.bind(('0.0.0.0', 0))
        port = s.getsockname()[1]
        print(f"Network test: UDP socket created on port {port}")
        s.close()
        return True
    except Exception as e:
        print(f"Network test failed: {e}")
        return False

if __name__ == "__main__":
    if test_network():
        print("Network connectivity test: PASS")
        sys.exit(0)
    else:
        print("Network connectivity test: FAIL")
        sys.exit(1)
EOF

chmod +x $PROJECT_DIR/test_connection.py

# Set permissions
sudo chown -R ec2-user:ec2-user $PROJECT_DIR

echo "User data script completed successfully!"
echo "Instance is ready for SRFT networking project."
echo "Project directory: $PROJECT_DIR"
echo "Python version: $(python3 --version)"
echo "Pip version: $(pip3 --version || echo 'pip not available')"