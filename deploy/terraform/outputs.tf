output "cluster_name" { value = aws_eks_cluster.this.name }
output "cluster_endpoint" { value = aws_eks_cluster.this.endpoint }
output "db_endpoint" { value = aws_db_instance.this.endpoint }
output "db_master_secret_arn" { value = aws_db_instance.this.master_user_secret[0].secret_arn }
output "app_role_arn" { value = aws_iam_role.app.arn }
output "app_secret_name" { value = aws_secretsmanager_secret.app.name }
