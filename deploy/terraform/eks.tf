resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_iam_role" "cluster" {
  name               = "${var.name}-eks-cluster"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["sts:AssumeRole", "sts:TagSession"], Principal = { Service = "eks.amazonaws.com" } }] })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = var.name
  version  = var.eks_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = length(var.eks_public_access_cidrs) > 0
    public_access_cidrs     = length(var.eks_public_access_cidrs) > 0 ? var.eks_public_access_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]
    provider { key_arn = aws_kms_key.this.arn }
  }

  access_config {
    authentication_mode = "API"
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  depends_on                = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.eks]
}

resource "aws_iam_role" "node" {
  name               = "${var.name}-eks-node"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }] })
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each   = toset(["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"])
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/${each.value}"
}

resource "aws_launch_template" "node" {
  name_prefix = "${var.name}-node-"
  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods cannot reach the node's instance credentials
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 50
      encrypted   = true
      kms_key_id  = aws_kms_key.this.arn
    }
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = aws_subnet.private[*].id
  instance_types  = var.node_instance_types
  ami_type        = "AL2023_ARM_64_STANDARD"
  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }
  scaling_config {
    min_size     = 3
    desired_size = 3
    max_size     = 9
  }
  update_config {
    max_unavailable = 1
  }
  depends_on = [aws_iam_role_policy_attachment.node]
}

# IRSA: pods assume IAM roles through the cluster's OIDC issuer, never node credentials.
data "aws_eks_cluster" "this" {
  name = aws_eks_cluster.this.name
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"] # IAM now trusts the issuer's CA directly; kept for older providers
}
