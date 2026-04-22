# Output values for SRFT networking infrastructure

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.allow_all.id
}

output "instance_ids" {
  description = "IDs of the EC2 instances"
  value       = aws_instance.srft_instance[*].id
}

output "instance_public_ips" {
  description = "Public IP addresses of the EC2 instances"
  value       = aws_eip.instance_eip[*].public_ip
}

output "instance_private_ips" {
  description = "Private IP addresses of the EC2 instances"
  value       = aws_instance.srft_instance[*].private_ip
}

output "instance_availability_zones" {
  description = "Availability zones of the EC2 instances"
  value       = aws_instance.srft_instance[*].availability_zone
}

output "generated_ssh_key" {
  description = "Generated SSH private key (if no key_name provided)"
  value       = var.key_name == "" ? tls_private_key.ssh_key[0].private_key_pem : "Using existing key pair: ${var.key_name}"
  sensitive   = true
}

output "ssh_key_name" {
  description = "SSH key pair name used for instances"
  value       = var.key_name != "" ? var.key_name : aws_key_pair.generated_key[0].key_name
}

output "session_manager_commands" {
  description = "AWS CLI commands to connect via Session Manager"
  value = [
    for i, instance in aws_instance.srft_instance :
    "aws ssm start-session --target ${instance.id}"
  ]
}

output "ssh_commands" {
  description = "SSH commands to connect to instances"
  value = [
    for i, ip in aws_eip.instance_eip[*].public_ip :
    "ssh -i ~/.ssh/${var.key_name != "" ? var.key_name : aws_key_pair.generated_key[0].key_name}.pem ec2-user@${ip}"
  ]
}

output "project_setup_instructions" {
  description = "Instructions for setting up the SRFT project on instances"
  value = <<-EOT

  SRFT Networking Project Infrastructure deployed successfully!

  Next steps:
  1. Copy project files to instances:
     For each instance, use SCP to copy the project directory:
     
     ${join("\n     ", [
  for i, ip in aws_eip.instance_eip[*].public_ip :
  "scp -r -i ~/.ssh/${var.key_name != "" ? var.key_name : aws_key_pair.generated_key[0].key_name}.pem ../. ec2-user@${ip}:/home/ec2-user/cs5700/"
  ])}

  2. Or use Session Manager and copy files manually:
     ${join("\n     ", [
  for i, instance in aws_instance.srft_instance :
  "aws ssm start-session --target ${instance.id}"
  ])}

  3. Update configuration:
     Edit config.py on each instance to use private IPs:
     - SERVER_IP: ${aws_instance.srft_instance[0].private_ip}
     - CLIENT_IP: ${aws_instance.srft_instance[1].private_ip}

  4. Test connectivity between instances using private IPs.

  Instance Details:
  ${join("\n  ", [
  for i, instance in aws_instance.srft_instance :
  "Instance ${i + 1}: ${instance.id} | Public IP: ${aws_eip.instance_eip[i].public_ip} | Private IP: ${instance.private_ip} | AZ: ${instance.availability_zone}"
])}

  EOT
}