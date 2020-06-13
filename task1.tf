provider "aws" {
  region = "ap-south-1"
  profile = "Vishterr"
}

variable "vish_key_name" {
  type = string
  default = "vish_terraform_test"
}

resource "tls_private_key" "vishkey" {
  algorithm   = "RSA"
   rsa_bits  = 2048
}

module "key_pair" {
  source = "terraform-aws-modules/key-pair/aws"

  key_name   = "vish_terraform_test"
  public_key = tls_private_key.vishkey.public_key_openssh
}
output  "os_key"{
  value =  tls_private_key.vishkey.public_key_openssh
}

// Creating aws security resource
resource "aws_security_group" "allow_tcp" {
  name        = "allow_tcp"
  description = "Allow TCP inbound traffic"
  vpc_id      = "vpc-06968b6e"

  ingress {
    description = "TCP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

ingress {
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS from VPC"
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
    Name = "allow_tcp"
  }
}


resource "aws_instance" "web" {
 
depends_on = [
       tls_private_key.vishkey,aws_security_group.allow_tcp
  ]
 
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name =  "mykey"
  vpc_security_group_ids = ["${aws_security_group.allow_tcp.id}"]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("C:/Users/visha/keyslocation/mykey.pem")
    host     = aws_instance.web.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }

  tags = {
    Name = "vishos1"
  }

}


resource "aws_ebs_volume" "esb1" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  tags = {
    Name = "vishebs"
  }
}

resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdh"
  volume_id   = "${aws_ebs_volume.esb1.id}"
  instance_id = "${aws_instance.web.id}"
  force_detach = true
}

output "myos_ip" {
  value = aws_instance.web.public_ip
}


resource "null_resource" "nulllocal2"  {
	provisioner "local-exec" {
	    command = "echo  ${aws_instance.web.public_ip} > publicip.txt"
  	}
}

variable  "enter_bucket_name"{
  type = string
}

resource "aws_s3_bucket" "tera_bucket" {
 bucket = var.enter_bucket_name
  acl    = "private"
}

// Block Public Access
resource "aws_s3_bucket_public_access_block" "s3BlockPublicAccess" {
  bucket = "${aws_s3_bucket.tera_bucket.id}"

  block_public_acls   = true
  block_public_policy = true
  restrict_public_buckets = true
}

//
locals {
  s3_origin_id = "myS3Origin"
}

resource "aws_s3_bucket_policy" "s3BucketPolicy" {
  bucket = "${aws_s3_bucket.tera_bucket.id}"
  policy = "${data.aws_iam_policy_document.s3_policy.json}"
}


resource "aws_s3_bucket_object" "bucketObject" {
  bucket = var.enter_bucket_name
  key    = "Wedding.jpg"
  source = "D:/images/vishimages/Wedding.jpg"
}

// Creating Origin Access Identity for CloudFront
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Tera Access Identity"
}

resource "aws_cloudfront_distribution" "s3_distribution" {

  depends_on = [
    aws_s3_bucket_object.bucketObject
  ]

  origin {
    domain_name = "${aws_s3_bucket.tera_bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"

    s3_origin_config {
      # origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Terra Access Identity"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["CA"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  retain_on_delete = true
}

// AWS Bucket Policy for CloudFront
data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tera_bucket.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.tera_bucket.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}


resource "null_resource" "nullremote3"  {

depends_on = [
    aws_volume_attachment.ebs_att
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  file("C:/Users/visha/keyslocation/mykey.pem")
    host     = aws_instance.web.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
     "sudo git clone https://github.com/Vishal-exe123/cloudterraform1.git /var/www/html/",
    "sudo systemctl  restart  httpd"
    ]
  }
}

output  "cloudfront_url"{
   value = aws_cloudfront_distribution.s3_distribution.domain_name
}

output  "bucketkey_url"{
   value =aws_s3_bucket_object.bucketObject.key
}