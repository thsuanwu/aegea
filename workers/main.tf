provider "aws" {
  region = "us-west-2"
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

resource "aws_iam_role" "fargate_service" {
  name = "akislyuk-test"
  assume_role_policy = file("trust_policy.json")
}

resource "aws_iam_role_policy_attachment" "fargate_service_policy1" {
  role = aws_iam_role.fargate_service.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

resource "aws_iam_role_policy_attachment" "fargate_service_policy2" {
  role = aws_iam_role.fargate_service.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

# TODO: is arn:aws:iam::732052188396:role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService necessary to attach?

resource "aws_ecs_cluster" "worker_cluster" {
  name = "akislyuk-test"
  capacity_providers = toset(["FARGATE"])
}

resource "aws_ecs_task_definition" "worker" {
  family = "worker"
  requires_compatibilities = toset(["FARGATE"])
  cpu = "1 vCPU"
  memory = "2 GB"
  network_mode = "awsvpc"
  container_definitions = file("worker_container_defn.json")
  execution_role_arn = aws_iam_role.fargate_service.arn
  volume {
    name = "scratch"
  }
}

resource "aws_ecs_service" "worker" {
  name = "akislyuk-test"
  launch_type = "FARGATE"
  cluster = aws_ecs_cluster.worker_cluster.id
  task_definition = aws_ecs_task_definition.worker.id
  desired_count = 1
  network_configuration {
    subnets = [for subnet in aws_subnet.worker: subnet.id]
    security_groups = [aws_security_group.worker.id]
    assign_public_ip = true
  }
  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = 4
  min_capacity       = 1
  resource_id        = "service/akislyuk-test/akislyuk-test"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_policy" {
  name               = "akislyuk-test"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Maximum"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}
