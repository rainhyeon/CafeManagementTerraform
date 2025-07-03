// Filename: variables.tf
variable "region" {
  description = "region"
  default     = "ap-northeast-2"
}

variable "db_name" {
  description = "DB name"
  default     = "Cafe_Management_db"
}

variable "db_username" {
  description = "master user"
  default     = "admin"
}

variable "db_password" {
  description = "master password"
  sensitive   = true
  default     = "password"
}

variable "domain_name" {
  description = "Domain name"
  default     = "rainhyeon.store"
}

// Filename: terraform.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

// Filename: vpc.tf
resource "aws_vpc" "Cafe_Management_vpc_1" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "Cafe_Management_vpc_1"
  }
}

resource "aws_internet_gateway" "Cafe_Management_igw_1" {
  vpc_id = aws_vpc.Cafe_Management_vpc_1.id

  tags = {
    Name = "Cafe_Management_igw_1"
  }
}

// Filename: subnets.tf
resource "aws_subnet" "Cafe_Management_public_subnet_1" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.30.0/24"
  availability_zone                           = "ap-northeast-2a"
  map_public_ip_on_launch                     = true
  enable_resource_name_dns_a_record_on_launch = true

  depends_on = [aws_internet_gateway.Cafe_Management_igw_1]

  tags = {
    Name = "Cafe_Management_public_subnet_1"
  }
}

resource "aws_subnet" "Cafe_Management_public_subnet_2" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.31.0/24"
  availability_zone                           = "ap-northeast-2c"
  map_public_ip_on_launch                     = true
  enable_resource_name_dns_a_record_on_launch = true

  depends_on = [aws_internet_gateway.Cafe_Management_igw_1]

  tags = {
    Name = "Cafe_Management_public_subnet_2"
  }
}

resource "aws_subnet" "Cafe_Management_web_subnet_1" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.10.0/24"
  availability_zone                           = "ap-northeast-2a"
  enable_resource_name_dns_a_record_on_launch = true

  tags = {
    Name = "Cafe_Management_web_subnet_1"
  }
}

resource "aws_subnet" "Cafe_Management_web_subnet_2" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.11.0/24"
  availability_zone                           = "ap-northeast-2c"
  enable_resource_name_dns_a_record_on_launch = true

  tags = {
    Name = "Cafe_Management_web_subnet_2"
  }
}

resource "aws_subnet" "Cafe_Management_db_subnet_1" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.20.0/24"
  availability_zone                           = "ap-northeast-2a"
  enable_resource_name_dns_a_record_on_launch = true

  tags = {
    Name = "Cafe_Management_db_subnet_1"
  }
}

resource "aws_subnet" "Cafe_Management_db_subnet_2" {
  vpc_id                                      = aws_vpc.Cafe_Management_vpc_1.id
  cidr_block                                  = "10.30.21.0/24"
  availability_zone                           = "ap-northeast-2c"
  enable_resource_name_dns_a_record_on_launch = true

  tags = {
    Name = "Cafe_Management_db_subnet_2"
  }
}

// Filename: nat_gateway.tf
resource "aws_eip" "Cafe_Management_eip_1" {
  domain = "vpc"

  tags = {
    Name = "Cafe_Management_eip_1"
  }
}

resource "aws_eip" "Cafe_Management_eip_2" {
  domain = "vpc"

  tags = {
    Name = "Cafe_Management_eip_2"
  }
}

resource "aws_nat_gateway" "Cafe_Management_nat_gateway_1" {
  allocation_id = aws_eip.Cafe_Management_eip_1.id
  subnet_id     = aws_subnet.Cafe_Management_public_subnet_1.id

  tags = {
    Name = "Cafe_Management_nat_gateway_1"
  }

  depends_on = [aws_internet_gateway.Cafe_Management_igw_1]
}

resource "aws_nat_gateway" "Cafe_Management_nat_gateway_2" {
  allocation_id = aws_eip.Cafe_Management_eip_2.id
  subnet_id     = aws_subnet.Cafe_Management_public_subnet_2.id

  tags = {
    Name = "Cafe_Management_nat_gateway_2"
  }

  depends_on = [aws_internet_gateway.Cafe_Management_igw_1]
}

// Filename: route_tables.tf
resource "aws_route_table" "Cafe_Management_public_rt_1" {
  vpc_id = aws_vpc.Cafe_Management_vpc_1.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Cafe_Management_igw_1.id
  }

  tags = {
    Name = "Cafe_Management_public_rt_1"
  }
}

resource "aws_route_table" "Cafe_Management_web_rt_1" {
  vpc_id = aws_vpc.Cafe_Management_vpc_1.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.Cafe_Management_nat_gateway_1.id
  }

  tags = {
    Name = "Cafe_Management_web_rt_1"
  }
}

resource "aws_route_table" "Cafe_Management_web_rt_2" {
  vpc_id = aws_vpc.Cafe_Management_vpc_1.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.Cafe_Management_nat_gateway_2.id
  }

  tags = {
    Name = "Cafe_Management_web_rt_2"
  }
}

resource "aws_route_table" "Cafe_Management_db_rt_1" {
  vpc_id = aws_vpc.Cafe_Management_vpc_1.id

  tags = {
    Name = "Cafe_Management_db_rt_1"
  }
}

resource "aws_route_table_association" "Cafe_Management_public_rta_1" {
  subnet_id      = aws_subnet.Cafe_Management_public_subnet_1.id
  route_table_id = aws_route_table.Cafe_Management_public_rt_1.id
}

resource "aws_route_table_association" "Cafe_Management_public_rta_2" {
  subnet_id      = aws_subnet.Cafe_Management_public_subnet_2.id
  route_table_id = aws_route_table.Cafe_Management_public_rt_1.id
}

resource "aws_route_table_association" "Cafe_Management_web_rta_1" {
  subnet_id      = aws_subnet.Cafe_Management_web_subnet_1.id
  route_table_id = aws_route_table.Cafe_Management_web_rt_1.id
}

resource "aws_route_table_association" "Cafe_Management_web_rta_2" {
  subnet_id      = aws_subnet.Cafe_Management_web_subnet_2.id
  route_table_id = aws_route_table.Cafe_Management_web_rt_2.id
}

resource "aws_route_table_association" "Cafe_Management_db_rta_1" {
  subnet_id      = aws_subnet.Cafe_Management_db_subnet_1.id
  route_table_id = aws_route_table.Cafe_Management_db_rt_1.id
}

resource "aws_route_table_association" "Cafe_Management_db_rta_2" {
  subnet_id      = aws_subnet.Cafe_Management_db_subnet_2.id
  route_table_id = aws_route_table.Cafe_Management_db_rt_1.id
}

// Filename: security_groups.tf
resource "aws_security_group" "Cafe_Management_alb_sg_1" {
  name        = "Cafe_Management_alb_sg_1"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.Cafe_Management_vpc_1.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Cafe_Management_alb_sg_1"
  }
}

resource "aws_security_group" "Cafe_Management_bastion_sg_1" {
  name        = "Cafe_Management_bastion_sg_1"
  description = "Security group for Bastion"
  vpc_id      = aws_vpc.Cafe_Management_vpc_1.id

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

  tags = {
    Name = "Cafe_Management_bastion_sg_1"
  }
}

resource "aws_security_group" "Cafe_Management_web_sg_1" {
  name        = "Cafe_Management_web_sg_1"
  description = "Security group for Web servers"
  vpc_id      = aws_vpc.Cafe_Management_vpc_1.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.Cafe_Management_alb_sg_1.id]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.Cafe_Management_alb_sg_1.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.Cafe_Management_bastion_sg_1.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Cafe_Management_web_sg_1"
  }
}

resource "aws_security_group" "Cafe_Management_db_sg_1" {
  name        = "Cafe_Management_db_sg_1"
  description = "Security group for Database"
  vpc_id      = aws_vpc.Cafe_Management_vpc_1.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.Cafe_Management_web_sg_1.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Cafe_Management_db_sg_1"
  }
}

// Filename: policy.tf
resource "aws_iam_policy" "dms_vpc_custom_policy" {
  name        = "dms-vpc-custom-policy"
  description = "Allow DMS to manage EC2 network interfaces"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:AttachNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}


// Filename: iam.tf

resource "aws_iam_role" "dms_assessment_role" {
  name = "DMSAssessmentRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "dms.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "dms_assessment_policy" {
  name = "DMSAssessmentPolicy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:*"],
        Resource = ["arn:aws:s3:::liftify-assessment-*", "arn:aws:s3:::liftify-assessment-*/*"]
      },
      {
        Effect = "Allow",
        Action = ["dms:*"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.dms_assessment_role.name
  policy_arn = aws_iam_policy.dms_assessment_policy.arn
}


resource "aws_iam_role" "dms_vpc_role" {
  name = "dms-vpc-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "dms.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "dms-vpc-role"
  }
}

resource "aws_iam_role_policy_attachment" "dms_vpc_custom_attach" {
  role       = aws_iam_role.dms_vpc_role.name
  policy_arn = aws_iam_policy.dms_vpc_custom_policy.arn
}


resource "aws_iam_role" "Cafe_Management_ec2_role_1" {
  name = "Cafe_Management_ec2_role_1"

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
    Name = "Cafe_Management_ec2_role_1"
  }
}

resource "aws_iam_role_policy_attachment" "Cafe_Management_ssm_policy_1" {
  role       = aws_iam_role.Cafe_Management_ec2_role_1.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "Cafe_Management_ec2_profile_1" {
  name = "Cafe_Management_ec2_profile_1"
  role = aws_iam_role.Cafe_Management_ec2_role_1.name

  tags = {
    Name = "Cafe_Management_ec2_profile_1"
  }
}

// Filename: acm.tf
resource "aws_acm_certificate" "Cafe_Management_cert_1" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "Cafe_Management_cert_1"
  }
}

resource "aws_route53_zone" "Cafe_Management_zone_1" {
  name = var.domain_name

  tags = {
    Name = "Cafe_Management_zone_1"
  }
}

resource "aws_route53_record" "Cafe_Management_cert_validation_1" {
  for_each = {
    for dvo in aws_acm_certificate.Cafe_Management_cert_1.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.Cafe_Management_zone_1.zone_id
}

resource "aws_acm_certificate_validation" "Cafe_Management_cert_validation_1" {
  certificate_arn         = aws_acm_certificate.Cafe_Management_cert_1.arn
  validation_record_fqdns = [for record in aws_route53_record.Cafe_Management_cert_validation_1 : record.fqdn]
}

// Filename: alb.tf
resource "aws_lb" "Cafe_Management_alb_1" {
  name               = "Cafe-Management-alb-1"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.Cafe_Management_alb_sg_1.id]
  subnets            = [aws_subnet.Cafe_Management_public_subnet_1.id, aws_subnet.Cafe_Management_public_subnet_2.id]

  enable_deletion_protection = false

  tags = {
    Name = "Cafe_Management_alb_1"
  }
}

resource "aws_lb_target_group" "Cafe_Management_tg_1" {
  name     = "Cafe-Management-tg-1"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.Cafe_Management_vpc_1.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name = "Cafe_Management_tg_1"
  }
}

resource "aws_lb_listener" "Cafe_Management_listener_80_1" {
  load_balancer_arn = aws_lb.Cafe_Management_alb_1.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "Cafe_Management_listener_443_1" {
  load_balancer_arn = aws_lb.Cafe_Management_alb_1.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate_validation.Cafe_Management_cert_validation_1.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.Cafe_Management_tg_1.arn
  }
}

// Filename: ec2.tf
resource "aws_instance" "Cafe_Management_bastion_1" {
  ami                    = "ami-0c593c3690c32e925"
  instance_type          = "t3.medium"
  key_name               = null
  subnet_id              = aws_subnet.Cafe_Management_public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.Cafe_Management_bastion_sg_1.id]
 iam_instance_profile   = aws_iam_instance_profile.Cafe_Management_ec2_profile_1.name

  tags = {
    Name = "Cafe_Management_bastion_1"
  }
}

resource "aws_instance" "Cafe_Management_web_1" {
  ami                    = "ami-08943a151bd468f4e"
  instance_type          = "t3.medium"
  key_name               = null
  subnet_id              = aws_subnet.Cafe_Management_web_subnet_1.id
  vpc_security_group_ids = [aws_security_group.Cafe_Management_web_sg_1.id]
  iam_instance_profile   = aws_iam_instance_profile.Cafe_Management_ec2_profile_1.name

  tags = {
    Name = "Cafe_Management_web_1"
  }
}

resource "aws_instance" "Cafe_Management_web_2" {
  ami                    = "ami-08943a151bd468f4e"
  instance_type          = "t3.medium"
  key_name               = null
  subnet_id              = aws_subnet.Cafe_Management_web_subnet_2.id
  vpc_security_group_ids = [aws_security_group.Cafe_Management_web_sg_1.id]
  iam_instance_profile   = aws_iam_instance_profile.Cafe_Management_ec2_profile_1.name

  tags = {
    Name = "Cafe_Management_web_2"
  }
}

resource "aws_lb_target_group_attachment" "Cafe_Management_tg_attachment_1" {
  target_group_arn = aws_lb_target_group.Cafe_Management_tg_1.arn
  target_id        = aws_instance.Cafe_Management_web_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "Cafe_Management_tg_attachment_2" {
  target_group_arn = aws_lb_target_group.Cafe_Management_tg_1.arn
  target_id        = aws_instance.Cafe_Management_web_2.id
  port             = 80
}

// Filename: rds.tf
resource "aws_db_parameter_group" "Cafe_Management_db_param_group_1" {
  family = "mysql8.0"
  name   = "cafe-management-db-param-group-1"

  parameter {
    name  = "time_zone"
    value = "Asia/Seoul"
  }

  tags = {
    Name = "Cafe_Management_db_param_group_1"
  }
}

resource "aws_db_subnet_group" "Cafe_Management_db_subnet_group_1" {
  name       = "cafe-management-db-subnet-group-1"
  subnet_ids = [aws_subnet.Cafe_Management_db_subnet_1.id, aws_subnet.Cafe_Management_db_subnet_2.id]

  tags = {
    Name = "Cafe_Management_db_subnet_group_1"
  }
}

resource "aws_db_instance" "Cafe_Management_db" {
  identifier             = "cafe-management-db"
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.medium"
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = aws_db_parameter_group.Cafe_Management_db_param_group_1.name
  db_subnet_group_name   = aws_db_subnet_group.Cafe_Management_db_subnet_group_1.name
  vpc_security_group_ids = [aws_security_group.Cafe_Management_db_sg_1.id]
  skip_final_snapshot    = true
  multi_az               = true

  tags = {
    Name = "Cafe_Management_db"
  }
}

// Filename: route53.tf
resource "aws_route53_record" "Cafe_Management_www_onprem" {
  zone_id = aws_route53_zone.Cafe_Management_zone_1.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = ["34.22.91.176"]

  weighted_routing_policy {
    weight = 225
  }

  set_identifier = "www-onprem-weight-225"
}

resource "aws_route53_record" "Cafe_Management_www_alb" {
  zone_id = aws_route53_zone.Cafe_Management_zone_1.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.Cafe_Management_alb_1.dns_name
    zone_id                = aws_lb.Cafe_Management_alb_1.zone_id
    evaluate_target_health = true
  }

  weighted_routing_policy {
    weight = 0
  }

  set_identifier = "www-alb-weight-0"
}

// Filename: outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.Cafe_Management_vpc_1.id
}

output "alb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.Cafe_Management_alb_1.dns_name
}

output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = aws_route53_zone.Cafe_Management_zone_1.zone_id
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.Cafe_Management_db.endpoint
}

output "bastion_public_ip" {
  description = "Public IP of bastion host"
  value       = aws_instance.Cafe_Management_bastion_1.public_ip
}

