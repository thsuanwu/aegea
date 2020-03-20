provider "aws" {
  region = "us-west-2"
}

data "aws_ssm_parameter" "worker_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "worker" {
  cidr_block = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "akislyuk-test"
  }
}

resource "aws_internet_gateway" "worker" {
  vpc_id = aws_vpc.worker.id
  tags = {
    Name = "akislyuk-test"
  }
}

resource "aws_route" "worker" {
  route_table_id = aws_vpc.worker.default_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.worker.id
}

resource "aws_subnet" "worker" {
  for_each = toset(data.aws_availability_zones.available.names)
  vpc_id = aws_vpc.worker.id
  availability_zone = each.key
  cidr_block = cidrsubnet(aws_vpc.worker.cidr_block, 8, index(data.aws_availability_zones.available.names, each.key))
  map_public_ip_on_launch = true
  tags = {
    Name = "akislyuk-test"
  }
}

resource "aws_security_group" "worker" {
  name = "akislyuk-test"
  vpc_id = aws_vpc.worker.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "worker_ecs" {
  name = "akislyuk-test"
  assume_role_policy = file("trust_policy.json")
}

resource "aws_iam_role_policy_attachment" "worker_ecs_policy1" {
  role = aws_iam_role.worker_ecs.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

resource "aws_iam_role_policy_attachment" "worker_ecs_policy2" {
  role = aws_iam_role.worker_ecs.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "worker" {
  name = "akislyuk-test"
  role = aws_iam_role.worker_ecs.name
}

resource "aws_ecs_cluster" "worker_cluster" {
  name = "akislyuk-test"
  capacity_providers = toset([aws_ecs_capacity_provider.worker.name])
}

resource "aws_ecs_task_definition" "worker" {
  family = "worker"
  container_definitions = file("worker_container_defn.json")
  execution_role_arn = aws_iam_role.worker_ecs.arn
  volume {
    name = "scratch"
  }
}

resource "aws_ecs_service" "worker" {
  name = "akislyuk-test"
  launch_type = "EC2"
  cluster = aws_ecs_cluster.worker_cluster.id
  task_definition = aws_ecs_task_definition.worker.id
  desired_count = 1
  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_launch_template" "worker" {
  name_prefix   = "akislyuk-test"
  image_id      = data.aws_ssm_parameter.worker_ami.value
  instance_type = "t3.small"
  user_data = base64encode("#!/bin/bash\necho ECS_CLUSTER=akislyuk-test > /etc/ecs/ecs.config")
  iam_instance_profile {
    arn = aws_iam_instance_profile.worker.arn
  }
}

resource "aws_autoscaling_group" "worker" {
  name_prefix = "akislyuk-test"
  availability_zones = toset(data.aws_availability_zones.available.names)
  desired_capacity   = 2
  max_size           = 8
  min_size           = 1
  protect_from_scale_in = true

  launch_template {
    id      = aws_launch_template.worker.id
    version = "$Latest"
  }

  lifecycle {
    ignore_changes = [tag]
  }
}

resource "aws_ecs_capacity_provider" "worker" {
  name = "akislyuk-test2"

  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.worker.arn
    managed_termination_protection = "ENABLED"

    managed_scaling {
      maximum_scaling_step_size = 10
      minimum_scaling_step_size = 1
      status                    = "ENABLED"
      target_capacity           = 50
    }
  }
}
