resource "tls_private_key" "legacy_key" {
  # VULNERABILITY: RSA algorithm is Shor-vulnerable
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_lb_listener" "legacy_listener" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  
  # VULNERABILITY: Legacy TLS version
  ssl_policy        = "ELBSecurityPolicy-TLS-1-1-2017-01"
}

resource "google_kms_crypto_key" "vulnerable_key" {
  name     = "vul-key"
  key_ring = google_kms_key_ring.keyring.id
  
  # VULNERABILITY: RSA algorithm in Cloud KMS
  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "SOFTWARE"
  }
}
