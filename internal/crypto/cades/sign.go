package cades

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/smallstep/pkcs7"
)

func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		oid[i] = val
	}
	return oid, nil
}

type SignOpts struct {
	SigningTime time.Time
	Policy      *model.SignPolicy // nil if none
}

// SignDetached creates a CAdES detached signature
func SignDetached(ctx context.Context, signer crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate, content []byte, opts SignOpts) ([]byte, error) {
	log.Printf("DEBUG: Starting CAdES detached signing (content len: %d)", len(content))
	// 1. Initialize SignedData
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	// 2. Prepare SigningCertificateV2 Attribute
	certHash := sha256.Sum256(cert.Raw)
	log.Printf("DEBUG: Signer Cert: %s (%x)", cert.Subject.CommonName, certHash[:8])

	essCertV2 := ESSCertIDv2{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OidSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}, // Explicit NULL
		},
		CertHash: certHash[:],
	}

	signingCertV2 := SigningCertificateV2{
		Certs: []ESSCertIDv2{essCertV2},
	}

	signingCertV2Bytes, err := asn1.Marshal(signingCertV2)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signingCertificateV2: %w", err)
	}

	attrs := []pkcs7.Attribute{
		{
			Type:  OidSigningCertificateV2,
			Value: asn1.RawValue{FullBytes: signingCertV2Bytes},
		},
	}

	// 2.5 Add SignaturePolicyIdentifier if present
	if opts.Policy != nil && opts.Policy.OID != "" {
		policyOID, err := parseOID(opts.Policy.OID)
		if err == nil {
			hashBytes, _ := base64.StdEncoding.DecodeString(opts.Policy.Hash)
			
			sigPolicyID := SignaturePolicyIdentifier{
				SigPolicyID: policyOID,
				SigPolicyHash: SigPolicyHash{
					HashAlgorithm: pkix.AlgorithmIdentifier{
						Algorithm:  OidSHA256,
						Parameters: asn1.RawValue{Tag: asn1.TagNull},
					},
					HashValue: hashBytes,
				},
			}
			
			if opts.Policy.URI != "" {
				sigPolicyID.SigPolicyQualifiers = []SigPolicyQualifier{
					{
						SigPolicyQualifierID: OidSignaturePolicyQualifierCPS,
						Qualifier:            asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(opts.Policy.URI)},
					},
				}
			}

			sigPolicyBytes, err := asn1.Marshal(sigPolicyID)
			if err == nil {
				attrs = append(attrs, pkcs7.Attribute{
					Type:  OidSignaturePolicyIdentifier,
					Value: asn1.RawValue{FullBytes: sigPolicyBytes},
				})
			}
		}
	}

	// 3. Add Signer with Attributes
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: attrs,
	}

	if err := sd.AddSigner(cert, signer, config); err != nil {
		log.Printf("DEBUG: AddSigner failed: %v", err)
		return nil, fmt.Errorf("failed to add signer: %w", err)
	}

	// 4. Add Certificates (Chain)
	log.Printf("DEBUG: Adding %d certs to chain", len(chain))
	for _, c := range chain {
		sd.AddCertificate(c)
	}

	// 5. Detach Content
	sd.Detach()

	// 6. Finish (Sign)
	bytes, err := sd.Finish()
	if err != nil {
		log.Printf("DEBUG: pkcs7.Finish failed: %v", err)
		return nil, fmt.Errorf("failed to finish signature: %w", err)
	}

	log.Printf("DEBUG: Signing complete, signature size: %d", len(bytes))
	return bytes, nil
}
