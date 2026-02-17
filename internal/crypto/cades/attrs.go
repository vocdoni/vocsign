package cades

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// OID for id-aa-signingCertificateV2
var OidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
var OidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
var OidSignaturePolicyIdentifier = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}

type SigningCertificateV2 struct {
	Certs    []ESSCertIDv2
	Policies []PolicyInformation `asn1:"optional"`
}

type ESSCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"default:sha256"`
	CertHash      []byte
	IssuerSerial  IssuerSerial `asn1:"optional"`
}

type IssuerSerial struct {
	Issuer   asn1.RawValue
	Serial   asn1.RawValue
}

type PolicyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []interface{} `asn1:"optional"`
}

type SignaturePolicyIdentifier struct {
	SigPolicyID       asn1.ObjectIdentifier
	SigPolicyHash     SigPolicyHash
	SigPolicyQualifiers []SigPolicyQualifier `asn1:"optional"`
}

type SigPolicyHash struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashValue     []byte
}

type SigPolicyQualifier struct {
	SigPolicyQualifierID asn1.ObjectIdentifier
	Qualifier            asn1.RawValue
}

var OidSignaturePolicyQualifierCPS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}
var OidSignaturePolicyQualifierUserNotice = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 2}

// Helper to create the default SHA256 AlgorithmIdentifier
func NewAlgorithmIdentifierSHA256() pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{
		Algorithm: OidSHA256,
		Parameters: asn1.NullRawValue,
	}
}
