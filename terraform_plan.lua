➜  stage git:(main) ✗ terraform plan
data.aws_availability_zones.available: Reading...
module.db.module.db_instance.data.aws_partition.current: Reading...
module.ecs_service.data.aws_partition.current: Reading...
module.records.data.aws_route53_zone.this[0]: Reading...
data.aws_ssm_parameter.fluentbit: Reading...
module.db.module.db_instance.data.aws_iam_policy_document.enhanced_monitoring: Reading...
module.db.module.db_instance.data.aws_iam_policy_document.enhanced_monitoring: Read complete after 0s [id=76086537]
module.ecs_service.data.aws_iam_policy_document.task_exec[0]: Reading...
module.db.module.db_instance.data.aws_partition.current: Read complete after 0s [id=aws]
module.ecs_service.data.aws_caller_identity.current: Reading...
module.ecs_service.data.aws_iam_policy_document.tasks[0]: Reading...
module.ecs_service.data.aws_partition.current: Read complete after 0s [id=aws]
module.ecs_service.data.aws_iam_policy_document.task_exec_assume[0]: Reading...
module.ecs_service.data.aws_iam_policy_document.task_exec[0]: Read complete after 0s [id=1415633931]
module.ecs_service.data.aws_iam_policy_document.tasks[0]: Read complete after 0s [id=757765849]
module.ecs_service.data.aws_iam_policy_document.task_exec_assume[0]: Read complete after 0s [id=2291109037]
module.ecs_service.data.aws_region.current: Reading...
module.ecs_service.data.aws_region.current: Read complete after 0s [id=eu-west-1]
module.alb.data.aws_partition.current: Reading...
module.alb.data.aws_partition.current: Read complete after 0s [id=aws]
module.ecs_service.data.aws_caller_identity.current: Read complete after 0s [id=197710927426]
module.ecs_service.data.aws_iam_policy_document.tasks_assume[0]: Reading...
module.ecs_service.data.aws_iam_policy_document.tasks_assume[0]: Read complete after 0s [id=336052609]
data.aws_ssm_parameter.fluentbit: Read complete after 0s [id=/aws/service/aws-for-fluent-bit/stable]
data.aws_availability_zones.available: Read complete after 0s [id=eu-west-1]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform planned the following actions, but then encountered a problem:

  # aws_ecr_repository.nahuel_challenge will be created
  + resource "aws_ecr_repository" "nahuel_challenge" {
      + arn                  = (known after apply)
      + id                   = (known after apply)
      + image_tag_mutability = "MUTABLE"
      + name                 = "hostaway"
      + registry_id          = (known after apply)
      + repository_url       = (known after apply)
      + tags_all             = (known after apply)

      + image_scanning_configuration {
          + scan_on_push = true
        }
    }

  # aws_iam_policy.additional will be created
  + resource "aws_iam_policy" "additional" {
      + arn         = (known after apply)
      + id          = (known after apply)
      + name        = "hostaway-additional"
      + name_prefix = (known after apply)
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ec2:Describe*",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_service_discovery_http_namespace.this will be created
  + resource "aws_service_discovery_http_namespace" "this" {
      + arn         = (known after apply)
      + description = "CloudMap namespace for hostaway"
      + http_name   = (known after apply)
      + id          = (known after apply)
      + name        = "hostaway"
      + tags        = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all    = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.alb.aws_lb.this[0] will be created
  + resource "aws_lb" "this" {
      + arn                                                          = (known after apply)
      + arn_suffix                                                   = (known after apply)
      + desync_mitigation_mode                                       = "defensive"
      + dns_name                                                     = (known after apply)
      + drop_invalid_header_fields                                   = true
      + enable_deletion_protection                                   = false
      + enable_http2                                                 = true
      + enable_tls_version_and_cipher_suite_headers                  = false
      + enable_waf_fail_open                                         = false
      + enable_xff_client_port                                       = false
      + enforce_security_group_inbound_rules_on_private_link_traffic = (known after apply)
      + id                                                           = (known after apply)
      + idle_timeout                                                 = 60
      + internal                                                     = (known after apply)
      + ip_address_type                                              = (known after apply)
      + load_balancer_type                                           = "application"
      + name                                                         = "hostaway"
      + name_prefix                                                  = (known after apply)
      + preserve_host_header                                         = false
      + security_groups                                              = (known after apply)
      + subnets                                                      = (known after apply)
      + tags                                                         = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all                                                     = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + vpc_id                                                       = (known after apply)
      + xff_header_processing_mode                                   = "append"
      + zone_id                                                      = (known after apply)

      + timeouts {}
    }

  # module.alb.aws_lb_listener.this["ex_http"] will be created
  + resource "aws_lb_listener" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 80
      + protocol          = "HTTP"
      + ssl_policy        = (known after apply)
      + tags              = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all          = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # module.alb.aws_lb_target_group.this["ex_ecs"] will be created
  + resource "aws_lb_target_group" "this" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = (known after apply)
      + deregistration_delay               = "5"
      + id                                 = (known after apply)
      + ip_address_type                    = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancer_arns                 = (known after apply)
      + load_balancing_algorithm_type      = (known after apply)
      + load_balancing_anomaly_mitigation  = (known after apply)
      + load_balancing_cross_zone_enabled  = "true"
      + name                               = (known after apply)
      + name_prefix                        = (known after apply)
      + port                               = 80
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTP"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags                               = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all                           = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + target_type                        = "ip"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = true
          + healthy_threshold   = 5
          + interval            = 30
          + matcher             = "200"
          + path                = "/"
          + port                = "traffic-port"
          + protocol            = "HTTP"
          + timeout             = 5
          + unhealthy_threshold = 2
        }
    }

  # module.alb.aws_route53_record.this["service"] will be created
  + resource "aws_route53_record" "this" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "invo_service.example.com"
      + type            = "A"
      + zone_id         = "XASDGVSADSDAW"

      + alias {
          + evaluate_target_health = true
          + name                   = (known after apply)
          + zone_id                = (known after apply)
        }
    }

  # module.alb.aws_security_group.this[0] will be created
  + resource "aws_security_group" "this" {
      + arn                    = (known after apply)
      + description            = "Security group for hostaway application load balancer"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "hostaway-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all               = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + vpc_id                 = (known after apply)
    }

  # module.alb.aws_vpc_security_group_egress_rule.this["all"] will be created
  + resource "aws_vpc_security_group_egress_rule" "this" {
      + arn                    = (known after apply)
      + cidr_ipv4              = "10.0.0.0/16"
      + id                     = (known after apply)
      + ip_protocol            = "-1"
      + security_group_id      = (known after apply)
      + security_group_rule_id = (known after apply)
      + tags                   = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all               = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
    }

  # module.alb.aws_vpc_security_group_ingress_rule.this["all_http"] will be created
  + resource "aws_vpc_security_group_ingress_rule" "this" {
      + arn                    = (known after apply)
      + cidr_ipv4              = "0.0.0.0/0"
      + from_port              = 80
      + id                     = (known after apply)
      + ip_protocol            = "tcp"
      + security_group_id      = (known after apply)
      + security_group_rule_id = (known after apply)
      + tags                   = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + tags_all               = {
          + "GithubRepo"            = "terraform-aws-eks"
          + "Name"                  = "hostaway"
          + "terraform-aws-modules" = "alb"
        }
      + to_port                = 80
    }

  # module.cdn.aws_cloudfront_distribution.this[0] will be created
  + resource "aws_cloudfront_distribution" "this" {
      + aliases                         = [
          + "cdn.hostaway.com",
        ]
      + arn                             = (known after apply)
      + caller_reference                = (known after apply)
      + comment                         = "My awesome CloudFront"
      + continuous_deployment_policy_id = (known after apply)
      + domain_name                     = (known after apply)
      + enabled                         = true
      + etag                            = (known after apply)
      + hosted_zone_id                  = (known after apply)
      + http_version                    = "http2"
      + id                              = (known after apply)
      + in_progress_validation_batches  = (known after apply)
      + is_ipv6_enabled                 = false
      + last_modified_time              = (known after apply)
      + price_class                     = "PriceClass_All"
      + retain_on_delete                = false
      + staging                         = false
      + status                          = (known after apply)
      + tags_all                        = (known after apply)
      + trusted_key_groups              = (known after apply)
      + trusted_signers                 = (known after apply)
      + wait_for_deployment             = false

      + default_cache_behavior {
          + allowed_methods        = [
              + "GET",
              + "HEAD",
              + "OPTIONS",
            ]
          + cached_methods         = [
              + "GET",
              + "HEAD",
            ]
          + compress               = true
          + default_ttl            = (known after apply)
          + max_ttl                = (known after apply)
          + min_ttl                = 0
          + target_origin_id       = "invo_service"
          + trusted_key_groups     = (known after apply)
          + trusted_signers        = (known after apply)
          + viewer_protocol_policy = "allow-all"

          + forwarded_values {
              + headers                 = (known after apply)
              + query_string            = true
              + query_string_cache_keys = []

              + cookies {
                  + forward           = "none"
                  + whitelisted_names = (known after apply)
                }
            }
        }

      + logging_config {
          + bucket          = "logs-my-cdn.s3.amazonaws.com"
          + include_cookies = false
        }

      + ordered_cache_behavior {
          + allowed_methods        = [
              + "GET",
              + "HEAD",
              + "OPTIONS",
            ]
          + cached_methods         = [
              + "GET",
              + "HEAD",
            ]
          + compress               = true
          + default_ttl            = (known after apply)
          + max_ttl                = (known after apply)
          + min_ttl                = 0
          + path_pattern           = "/static/*"
          + target_origin_id       = "s3_one"
          + viewer_protocol_policy = "redirect-to-https"

          + forwarded_values {
              + headers                 = (known after apply)
              + query_string            = true
              + query_string_cache_keys = []

              + cookies {
                  + forward = "none"
                }
            }
        }

      + origin {
          + connection_attempts = 3
          + connection_timeout  = 10
          + domain_name         = "invo_service.hostaway.com"
          + origin_id           = "invo_service"

          + custom_origin_config {
              + http_port                = 80
              + https_port               = 443
              + origin_keepalive_timeout = 5
              + origin_protocol_policy   = "match-viewer"
              + origin_read_timeout      = 30
              + origin_ssl_protocols     = [
                  + "TLSv1",
                  + "TLSv1.1",
                  + "TLSv1.2",
                ]
            }
        }
      + origin {
          + connection_attempts = 3
          + connection_timeout  = 10
          + domain_name         = "my-s3-bycket.s3.amazonaws.com"
          + origin_id           = "s3_one"

          + s3_origin_config {
              + origin_access_identity = (known after apply)
            }
        }

      + restrictions {
          + geo_restriction {
              + locations        = (known after apply)
              + restriction_type = "none"
            }
        }

      + viewer_certificate {
          + acm_certificate_arn      = "arn:aws:acm:eu-north-1:135367859851:certificate/1032b155-22da-4ae0-9f69-e206f825458b"
          + minimum_protocol_version = "TLSv1"
          + ssl_support_method       = "sni-only"
        }
    }

  # module.cdn.aws_cloudfront_origin_access_identity.this["s3_bucket_one"] will be created
  + resource "aws_cloudfront_origin_access_identity" "this" {
      + caller_reference                = (known after apply)
      + cloudfront_access_identity_path = (known after apply)
      + comment                         = "My awesome CloudFront can access"
      + etag                            = (known after apply)
      + iam_arn                         = (known after apply)
      + id                              = (known after apply)
      + s3_canonical_user_id            = (known after apply)
    }

  # module.ecs_cluster.aws_cloudwatch_log_group.this[0] will be created
  + resource "aws_cloudwatch_log_group" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + log_group_class   = (known after apply)
      + name              = "/aws/ecs/hostaway_stage"
      + name_prefix       = (known after apply)
      + retention_in_days = 90
      + skip_destroy      = false
      + tags              = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all          = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.ecs_cluster.aws_ecs_cluster.this[0] will be created
  + resource "aws_ecs_cluster" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + name     = "hostaway_stage"
      + tags     = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }

      + configuration {
          + execute_command_configuration {
              + logging = "DEFAULT"
            }
        }

      + setting {
          + name  = "containerInsights"
          + value = "enabled"
        }
    }

  # module.ecs_cluster.aws_ecs_cluster_capacity_providers.this[0] will be created
  + resource "aws_ecs_cluster_capacity_providers" "this" {
      + capacity_providers = [
          + "FARGATE",
          + "FARGATE_SPOT",
        ]
      + cluster_name       = "hostaway_stage"
      + id                 = (known after apply)

      + default_capacity_provider_strategy {
          + base              = 0
          + capacity_provider = "FARGATE_SPOT"
          + weight            = 50
        }
      + default_capacity_provider_strategy {
          + base              = 20
          + capacity_provider = "FARGATE"
          + weight            = 50
        }
    }

  # module.ecs_service.data.aws_ecs_task_definition.this[0] will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_ecs_task_definition" "this" {
      + arn                  = (known after apply)
      + arn_without_revision = (known after apply)
      + execution_role_arn   = (known after apply)
      + family               = (known after apply)
      + id                   = (known after apply)
      + network_mode         = (known after apply)
      + revision             = (known after apply)
      + status               = (known after apply)
      + task_definition      = "hostaway_stage"
      + task_role_arn        = (known after apply)
    }

  # module.ecs_service.data.aws_subnet.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_subnet" "this" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = (known after apply)
      + availability_zone                              = (known after apply)
      + availability_zone_id                           = (known after apply)
      + available_ip_address_count                     = (known after apply)
      + cidr_block                                     = (known after apply)
      + customer_owned_ipv4_pool                       = (known after apply)
      + default_for_az                                 = (known after apply)
      + enable_dns64                                   = (known after apply)
      + enable_lni_at_device_index                     = (known after apply)
      + enable_resource_name_dns_a_record_on_launch    = (known after apply)
      + enable_resource_name_dns_aaaa_record_on_launch = (known after apply)
      + id                                             = (known after apply)
      + ipv6_cidr_block                                = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = (known after apply)
      + map_customer_owned_ip_on_launch                = (known after apply)
      + map_public_ip_on_launch                        = (known after apply)
      + outpost_arn                                    = (known after apply)
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + state                                          = (known after apply)
      + tags                                           = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # module.ecs_service.aws_appautoscaling_policy.this["cpu"] will be created
  + resource "aws_appautoscaling_policy" "this" {
      + alarm_arns         = (known after apply)
      + arn                = (known after apply)
      + id                 = (known after apply)
      + name               = "cpu"
      + policy_type        = "TargetTrackingScaling"
      + resource_id        = (known after apply)
      + scalable_dimension = "ecs:service:DesiredCount"
      + service_namespace  = "ecs"

      + target_tracking_scaling_policy_configuration {
          + disable_scale_in   = false
          + scale_in_cooldown  = 300
          + scale_out_cooldown = 60
          + target_value       = 75

          + predefined_metric_specification {
              + predefined_metric_type = "ECSServiceAverageCPUUtilization"
            }
        }
    }

  # module.ecs_service.aws_appautoscaling_policy.this["memory"] will be created
  + resource "aws_appautoscaling_policy" "this" {
      + alarm_arns         = (known after apply)
      + arn                = (known after apply)
      + id                 = (known after apply)
      + name               = "memory"
      + policy_type        = "TargetTrackingScaling"
      + resource_id        = (known after apply)
      + scalable_dimension = "ecs:service:DesiredCount"
      + service_namespace  = "ecs"

      + target_tracking_scaling_policy_configuration {
          + disable_scale_in   = false
          + scale_in_cooldown  = 300
          + scale_out_cooldown = 60
          + target_value       = 75

          + predefined_metric_specification {
              + predefined_metric_type = "ECSServiceAverageMemoryUtilization"
            }
        }
    }

  # module.ecs_service.aws_appautoscaling_target.this[0] will be created
  + resource "aws_appautoscaling_target" "this" {
      + arn                = (known after apply)
      + id                 = (known after apply)
      + max_capacity       = 10
      + min_capacity       = 1
      + resource_id        = (known after apply)
      + role_arn           = (known after apply)
      + scalable_dimension = "ecs:service:DesiredCount"
      + service_namespace  = "ecs"
      + tags               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.ecs_service.aws_ecs_service.this[0] will be created
  + resource "aws_ecs_service" "this" {
      + cluster                            = (known after apply)
      + deployment_maximum_percent         = 200
      + deployment_minimum_healthy_percent = 66
      + desired_count                      = 1
      + enable_ecs_managed_tags            = true
      + enable_execute_command             = true
      + force_new_deployment               = true
      + iam_role                           = (known after apply)
      + id                                 = (known after apply)
      + launch_type                        = "FARGATE"
      + name                               = "hostaway_stage"
      + platform_version                   = (known after apply)
      + scheduling_strategy                = "REPLICA"
      + tags                               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + task_definition                    = (known after apply)
      + triggers                           = (known after apply)
      + wait_for_steady_state              = false

      + load_balancer {
          + container_name   = "main"
          + container_port   = 80
          + target_group_arn = (known after apply)
        }

      + network_configuration {
          + assign_public_ip = false
          + security_groups  = (known after apply)
          + subnets          = (known after apply)
        }

      + timeouts {}
    }

  # module.ecs_service.aws_ecs_task_definition.this[0] will be created
  + resource "aws_ecs_task_definition" "this" {
      + arn                      = (known after apply)
      + arn_without_revision     = (known after apply)
      + container_definitions    = jsonencode([])
      + cpu                      = "1024"
      + execution_role_arn       = (known after apply)
      + family                   = "hostaway_stage"
      + id                       = (known after apply)
      + memory                   = "4096"
      + network_mode             = "awsvpc"
      + requires_compatibilities = [
          + "FARGATE",
        ]
      + revision                 = (known after apply)
      + skip_destroy             = false
      + tags                     = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                 = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + task_role_arn            = (known after apply)
      + track_latest             = false

      + runtime_platform {
          + cpu_architecture        = "X86_64"
          + operating_system_family = "LINUX"
        }
    }

  # module.ecs_service.aws_iam_policy.task_exec[0] will be created
  + resource "aws_iam_policy" "task_exec" {
      + arn         = (known after apply)
      + description = "Task execution role IAM policy"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "hostaway_stage-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "logs:PutLogEvents",
                          + "logs:CreateLogStream",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "Logs"
                    },
                  + {
                      + Action   = [
                          + "ecr:GetDownloadUrlForLayer",
                          + "ecr:GetAuthorizationToken",
                          + "ecr:BatchGetImage",
                          + "ecr:BatchCheckLayerAvailability",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "ECR"
                    },
                  + {
                      + Action   = "ssm:GetParameters"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:ssm:*:*:parameter/*"
                      + Sid      = "GetSSMParams"
                    },
                  + {
                      + Action   = "secretsmanager:GetSecretValue"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:secretsmanager:*:*:secret:*"
                      + Sid      = "GetSecrets"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags        = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all    = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.ecs_service.aws_iam_role.task_exec[0] will be created
  + resource "aws_iam_role" "task_exec" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ecs-tasks.amazonaws.com"
                        }
                      + Sid       = "ECSTaskExecutionAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "Task execution role for hostaway_stage"
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "hostaway_stage-"
      + path                  = "/"
      + tags                  = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all              = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + unique_id             = (known after apply)
    }

  # module.ecs_service.aws_iam_role.tasks[0] will be created
  + resource "aws_iam_role" "tasks" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Condition = {
                          + ArnLike      = {
                              + "aws:SourceArn" = "arn:aws:ecs:eu-west-1:197710927426:*"
                            }
                          + StringEquals = {
                              + "aws:SourceAccount" = "197710927426"
                            }
                        }
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ecs-tasks.amazonaws.com"
                        }
                      + Sid       = "ECSTasksAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "hostaway_stage-"
      + path                  = "/"
      + tags                  = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all              = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + unique_id             = (known after apply)
    }

  # module.ecs_service.aws_iam_role_policy.tasks[0] will be created
  + resource "aws_iam_role_policy" "tasks" {
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "hostaway_stage-"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ssmmessages:OpenDataChannel",
                          + "ssmmessages:OpenControlChannel",
                          + "ssmmessages:CreateDataChannel",
                          + "ssmmessages:CreateControlChannel",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "ECSExec"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role        = (known after apply)
    }

  # module.ecs_service.aws_iam_role_policy_attachment.task_exec[0] will be created
  + resource "aws_iam_role_policy_attachment" "task_exec" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.ecs_service.aws_security_group.this[0] will be created
  + resource "aws_security_group" "this" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "hostaway_stage-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway_stage"
        }
      + tags_all               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway_stage"
        }
      + vpc_id                 = (known after apply)
    }

  # module.ecs_service.aws_security_group_rule.this["alb_ingress"] will be created
  + resource "aws_security_group_rule" "this" {
      + description              = "Service port"
      + from_port                = 80
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 80
      + type                     = "ingress"
    }

  # module.ecs_service.aws_security_group_rule.this["egress_all"] will be created
  + resource "aws_security_group_rule" "this" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.security_group.aws_security_group.this_name_prefix[0] will be created
  + resource "aws_security_group" "this_name_prefix" {
      + arn                    = (known after apply)
      + description            = "Complete MySQL security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "hostaway-sg-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                 = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "15m"
        }
    }

  # module.security_group.aws_security_group_rule.ingress_with_cidr_blocks[0] will be created
  + resource "aws_security_group_rule" "ingress_with_cidr_blocks" {
      + cidr_blocks              = [
          + "10.0.0.0/16",
        ]
      + description              = "MySQL access from within VPC"
      + from_port                = 3306
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 3306
      + type                     = "ingress"
    }

  # module.vpc.aws_default_network_acl.this[0] will be created
  + resource "aws_default_network_acl" "this" {
      + arn                    = (known after apply)
      + default_network_acl_id = (known after apply)
      + id                     = (known after apply)
      + owner_id               = (known after apply)
      + tags                   = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                 = (known after apply)

      + egress {
          + action          = "allow"
          + from_port       = 0
          + ipv6_cidr_block = "::/0"
          + protocol        = "-1"
          + rule_no         = 101
          + to_port         = 0
        }
      + egress {
          + action     = "allow"
          + cidr_block = "0.0.0.0/0"
          + from_port  = 0
          + protocol   = "-1"
          + rule_no    = 100
          + to_port    = 0
        }

      + ingress {
          + action          = "allow"
          + from_port       = 0
          + ipv6_cidr_block = "::/0"
          + protocol        = "-1"
          + rule_no         = 101
          + to_port         = 0
        }
      + ingress {
          + action     = "allow"
          + cidr_block = "0.0.0.0/0"
          + from_port  = 0
          + protocol   = "-1"
          + rule_no    = 100
          + to_port    = 0
        }
    }

  # module.vpc.aws_default_route_table.default[0] will be created
  + resource "aws_default_route_table" "default" {
      + arn                    = (known after apply)
      + default_route_table_id = (known after apply)
      + id                     = (known after apply)
      + owner_id               = (known after apply)
      + route                  = (known after apply)
      + tags                   = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                 = (known after apply)

      + timeouts {
          + create = "5m"
          + update = "5m"
        }
    }

  # module.vpc.aws_default_security_group.this[0] will be created
  + resource "aws_default_security_group" "this" {
      + arn                    = (known after apply)
      + description            = (known after apply)
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc.aws_eip.nat[0] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = "vpc"
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all             = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc                  = (known after apply)
    }

  # module.vpc.aws_internet_gateway.this[0] will be created
  + resource "aws_internet_gateway" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id   = (known after apply)
    }

  # module.vpc.aws_nat_gateway.this[0] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id                      = (known after apply)
      + association_id                     = (known after apply)
      + connectivity_type                  = "public"
      + id                                 = (known after apply)
      + network_interface_id               = (known after apply)
      + private_ip                         = (known after apply)
      + public_ip                          = (known after apply)
      + secondary_private_ip_address_count = (known after apply)
      + secondary_private_ip_addresses     = (known after apply)
      + subnet_id                          = (known after apply)
      + tags                               = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[0] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.public_internet_gateway[0] will be created
  + resource "aws_route" "public_internet_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + gateway_id             = (known after apply)
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route_table.intra[0] will be created
  + resource "aws_route_table" "intra" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all         = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all         = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.public[0] will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all         = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table_association.intra[0] will be created
  + resource "aws_route_table_association" "intra" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.intra[1] will be created
  + resource "aws_route_table_association" "intra" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.intra[2] will be created
  + resource "aws_route_table_association" "intra" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[2] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[2] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_subnet.intra[0] will be created
  + resource "aws_subnet" "intra" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.52.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                                       = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.intra[1] will be created
  + resource "aws_subnet" "intra" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.53.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                                       = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.intra[2] will be created
  + resource "aws_subnet" "intra" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.54.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                                       = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.0.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.16.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[2] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.32.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"                      = "terraform-aws-eks"
          + "Name"                            = "hostaway"
          + "kubernetes.io/role/internal-elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.48.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.49.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[2] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.50.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + tags_all                                       = {
          + "GithubRepo"             = "terraform-aws-eks"
          + "Name"                   = "hostaway"
          + "kubernetes.io/role/elb" = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_vpc.this[0] will be created
  + resource "aws_vpc" "this" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.0.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + enable_network_address_usage_metrics = (known after apply)
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                             = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
    }

  # module.db.module.db_instance.aws_db_instance.this[0] will be created
  + resource "aws_db_instance" "this" {
      + address                               = (known after apply)
      + allocated_storage                     = 5
      + allow_major_version_upgrade           = false
      + apply_immediately                     = false
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_target                         = (known after apply)
      + backup_window                         = "03:00-06:00"
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_name                               = "NahuelChallengeDB"
      + db_subnet_group_name                  = (known after apply)
      + delete_automated_backups              = true
      + deletion_protection                   = true
      + domain_fqdn                           = (known after apply)
      + endpoint                              = (known after apply)
      + engine                                = "mysql"
      + engine_version                        = "8.0"
      + engine_version_actual                 = (known after apply)
      + final_snapshot_identifier             = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + iam_database_authentication_enabled   = true
      + id                                    = (known after apply)
      + identifier                            = "hostawaydb"
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t4g.large"
      + iops                                  = (known after apply)
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + listener_endpoint                     = (known after apply)
      + maintenance_window                    = "mon:00:00-mon:03:00"
      + manage_master_user_password           = true
      + master_user_secret                    = (known after apply)
      + master_user_secret_kms_key_id         = (known after apply)
      + max_allocated_storage                 = 20
      + monitoring_interval                   = 30
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = false
      + nchar_character_set_name              = (known after apply)
      + network_type                          = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = 3306
      + publicly_accessible                   = false
      + replica_mode                          = (known after apply)
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = false
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_encrypted                     = true
      + storage_throughput                    = (known after apply)
      + storage_type                          = (known after apply)
      + tags                                  = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all                              = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + timezone                              = (known after apply)
      + username                              = "master"
      + vpc_security_group_ids                = (known after apply)

      + timeouts {}
    }

  # module.db.module.db_instance.aws_iam_role.enhanced_monitoring[0] will be created
  + resource "aws_iam_role" "enhanced_monitoring" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "monitoring.rds.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "MyRDSMonitoringRole"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + tags_all              = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostaway"
        }
      + unique_id             = (known after apply)
    }

  # module.db.module.db_instance.aws_iam_role_policy_attachment.enhanced_monitoring[0] will be created
  + resource "aws_iam_role_policy_attachment" "enhanced_monitoring" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
      + role       = "MyRDSMonitoringRole"
    }

  # module.db.module.db_instance.random_id.snapshot_identifier[0] will be created
  + resource "random_id" "snapshot_identifier" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 4
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
      + keepers     = {
          + "id" = "hostawaydb"
        }
    }

  # module.db.module.db_option_group.aws_db_option_group.this[0] will be created
  + resource "aws_db_option_group" "this" {
      + arn                      = (known after apply)
      + engine_name              = "mysql"
      + id                       = (known after apply)
      + major_engine_version     = "8.0"
      + name                     = (known after apply)
      + name_prefix              = "hostawaydb-"
      + option_group_description = "hostawaydb option group"
      + tags                     = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }
      + tags_all                 = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }

      + timeouts {}
    }

  # module.db.module.db_parameter_group.aws_db_parameter_group.this[0] will be created
  + resource "aws_db_parameter_group" "this" {
      + arn         = (known after apply)
      + description = "hostawaydb parameter group"
      + family      = "mysql8.0"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "hostawaydb-"
      + tags        = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }
      + tags_all    = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }
    }

  # module.db.module.db_subnet_group.aws_db_subnet_group.this[0] will be created
  + resource "aws_db_subnet_group" "this" {
      + arn                     = (known after apply)
      + description             = "hostawaydb subnet group"
      + id                      = (known after apply)
      + name                    = (known after apply)
      + name_prefix             = "hostawaydb-"
      + subnet_ids              = (known after apply)
      + supported_network_types = (known after apply)
      + tags                    = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }
      + tags_all                = {
          + "GithubRepo" = "terraform-aws-eks"
          + "Name"       = "hostawaydb"
        }
      + vpc_id                  = (known after apply)
    }

Plan: 67 to add, 0 to change, 0 to destroy.