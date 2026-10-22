resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "db" {
  name        = "${var.name}-db"
  description = "PostgreSQL: reachable only from the EKS cluster"
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_eks" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "EKS pods"
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name}-pg16"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
}

resource "aws_db_instance" "this" {
  identifier                            = var.name
  engine                                = "postgres"
  engine_version                        = "16"
  instance_class                        = var.db_instance_class
  allocated_storage                     = 100
  max_allocated_storage                 = 1000
  storage_type                          = "gp3"
  storage_encrypted                     = true
  kms_key_id                            = aws_kms_key.this.arn
  db_name                               = "irg"
  username                              = "irg_owner" # migrations only; the app runs queries as the irg_app role (row-level security)
  manage_master_user_password           = true        # RDS stores and rotates it in Secrets Manager
  master_user_secret_kms_key_id         = aws_kms_key.this.arn
  iam_database_authentication_enabled   = true
  multi_az                              = true
  db_subnet_group_name                  = aws_db_subnet_group.this.name
  vpc_security_group_ids                = [aws_security_group.db.id]
  parameter_group_name                  = aws_db_parameter_group.this.name
  backup_retention_period               = 14
  deletion_protection                   = true
  skip_final_snapshot                   = false
  final_snapshot_identifier             = "${var.name}-final"
  copy_tags_to_snapshot                 = true
  auto_minor_version_upgrade            = true
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.this.arn
  performance_insights_retention_period = 7
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  publicly_accessible                   = false
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${var.name}-rds-monitoring"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "monitoring.rds.amazonaws.com" } }] })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
