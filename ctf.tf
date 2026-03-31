provider "aws" {
  region = "us-east-1"
}

# 1. DynamoDB Table (The Flag)
resource "aws_dynamodb_table" "flag_table" {
  name           = "GameData"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "ConfigID"

  attribute {
    name = "ConfigID"
    type = "S"
  }
}

resource "aws_dynamodb_table_item" "the_flag" {
  table_name = aws_dynamodb_table.flag_table.name
  hash_key   = aws_dynamodb_table.flag_table.hash_key

  item = <<ITEM
{
  "ConfigID": {"S": "SecretFlag"},
  "FlagValue": {"S": "CTF{M3tadat4_1s_Vulnerabl3_2026}"}
}
ITEM
}

# 2. IAM Role & Instance Profile
resource "aws_iam_role" "ec2_role" {
  name = "EC2-Web-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "dynamo_read" {
  name = "DynamoReadOnly"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:DescribeTable"]
      Resource = aws_dynamodb_table.flag_table.arn
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "EC2-Web-Profile"
  role = aws_iam_role.ec2_role.name
}

# 3. Networking (Security Group)
resource "aws_security_group" "ctf_sg" {
  name        = "ctf-web-sg"
  description = "Allow HTTP and SSH"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 4. EC2 Instance
resource "aws_instance" "vulnerable_node" {
  ami           = "ami-0c3389a4fa5bddaad" # Amazon Linux 2023 in us-east-1
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids = [aws_security_group.ctf_sg.id]

  # Allow IMDSv1 (Crucial for the challenge)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" 
    http_put_response_hop_limit = 1
  }

  user_data = <<-EOF
              #!/bin/bash
              dnf update -y
              dnf install -y python3-pip
              pip3 install flask requests
              cat << 'PY' > /home/ec2-user/app.py
              from flask import Flask, request
              import requests
              app = Flask(__name__)
              @app.route('/proxy')
              def proxy():
                  url = request.args.get('url')
                  if not url: return "Usage: /proxy?url=http://example.com"
                  try:
                      r = requests.get(url, timeout=3)
                      return r.text
                  except Exception as e:
                      return str(e), 500
              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=80)
              PY
              python3 /home/ec2-user/app.py &
              EOF

  tags = { Name = "Vulnerable-Bastion-CTF" }
}

output "public_ip" {
  value = aws_instance.vulnerable_node.public_ip
}