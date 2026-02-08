module github.com/shipping-app/core

go 1.21

require (
    github.com/google/uuid v1.3.0
    golang.org/x/crypto v0.12.0 // VULNERABILITY: Indirect usage of Shor-vulnerable curves
)

require (
    github.com/lib/pq v1.10.9 // indirect
    github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect VULNERABILITY: Weak JWT algorithms
)
