# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Create VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Create public subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# Create route table for public subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Associate route table with public subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Create security group allowing all traffic
resource "aws_security_group" "allow_all" {
  name        = "${var.project_name}-allow-all"
  description = "Allow all inbound and outbound traffic"
  vpc_id      = aws_vpc.main.id

  # Allow all inbound
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all inbound traffic"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-allow-all-sg"
  }
}

# IAM role for EC2 instances with Session Manager permissions
resource "aws_iam_role" "ec2_ssm_role" {
  name = "${var.project_name}-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ec2-ssm-role"
  }
}

# Attach AmazonSSMManagedInstanceCore policy
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach additional SSM policies for Session Manager
resource "aws_iam_role_policy_attachment" "ssm_session_manager" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Create instance profile
resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "${var.project_name}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Generate SSH key pair if not provided
resource "tls_private_key" "ssh_key" {
  count     = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Upload SSH public key to AWS if generated
resource "aws_key_pair" "generated_key" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.ssh_key[0].public_key_openssh
}

# Save generated SSH private key to local file (if generated)
resource "local_sensitive_file" "ssh_private_key" {
  count           = var.key_name == "" ? 1 : 0
  filename        = "${path.module}/srft-networking-key.pem"
  content         = tls_private_key.ssh_key[0].private_key_pem
  file_permission = "0600"
}

# User data script to install Python and setup environment
# (templatefile function used inline in aws_instance resource)

# Create EC2 instances
resource "aws_instance" "srft_instance" {
  count = var.instance_count

  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.allow_all.id]
  associate_public_ip_address = var.enable_public_ip
  iam_instance_profile        = aws_iam_instance_profile.ec2_ssm_profile.name
  key_name                    = var.key_name != "" ? var.key_name : (length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : null)

  user_data = templatefile("${path.module}/user_data.sh", {})

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2
  }

  tags = {
    Name = "${var.project_name}-instance-${count.index + 1}"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  # Ensure instance has internet access for SSM agent
  depends_on = [
    aws_internet_gateway.main,
    aws_route_table_association.public
  ]
}

# Elastic IPs for persistent public IPs
resource "aws_eip" "instance_eip" {
  count    = var.instance_count
  instance = aws_instance.srft_instance[count.index].id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-eip-${count.index + 1}"
  }
}