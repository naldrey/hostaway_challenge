data "aws_availability_zones" "available" {}

locals {
  name            = "hostaway"
  cluster_version = "1.29"
  region          = "eu-west-1"
  env             = "stage"
  container_port  = 80
  container_name  = "main"
  route53_zone_id = "XASDGVSADSDAW"
  subdomain       = "example.com"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    Name    = local.name
    GithubRepo = "terraform-aws-eks"
  }
}