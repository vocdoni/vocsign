package cades

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OID for id-aa-signatureTimeStampToken (RFC 3161 / CAdES-T).
var OidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// timeStampReq is an RFC 3161 TimeStampReq.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm asn1.RawValue
	HashedMessage []byte
}

// timeStampResp is the outer RFC 3161 TimeStampResp.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status int
}

// RequestTimestamp sends an RFC 3161 timestamp request to a TSA URL and returns
// the raw TimeStampToken (a CMS SignedData structure).
//
// Per ETSI EN 319 122-1 section 5.4, the timestamp is computed over the
// signature value (EncryptedDigest) from the first SignerInfo in the PKCS#7
// structure — NOT over the entire PKCS#7 DER.
//
// The pkcs7DER parameter is the complete PKCS#7 DER output from SignDetached.
// This function extracts the signature value internally.
func RequestTimestamp(tsaURL string, pkcs7DER []byte) ([]byte, error) {
	// Extract the signature value from the PKCS#7 SignerInfo.
	sigValue, err := extractSignatureValue(pkcs7DER)
	if err != nil {
		return nil, fmt.Errorf("extract signature value: %w", err)
	}

	// Hash the signature value per ETSI EN 319 122-1 section 5.4.
	hash := sha256.Sum256(sigValue)

	// Build the SHA-256 AlgorithmIdentifier as raw ASN.1.
	algID, err := asn1.Marshal(OidSHA256)
	if err != nil {
		return nil, fmt.Errorf("marshal SHA256 OID: %w", err)
	}
	algIDWithNull, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
	if err != nil {
		return nil, fmt.Errorf("marshal NULL: %w", err)
	}
	hashAlgBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(algID, algIDWithNull...),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal hash algorithm: %w", err)
	}

	// Build the TimeStampReq.
	tsReq := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: asn1.RawValue{FullBytes: hashAlgBytes},
			HashedMessage: hash[:],
		},
		CertReq: true,
	}

	reqDER, err := asn1.Marshal(tsReq)
	if err != nil {
		return nil, fmt.Errorf("marshal timestamp request: %w", err)
	}

	// Send to TSA.
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(tsaURL, "application/timestamp-query", bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("TSA request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSA returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, fmt.Errorf("read TSA response: %w", err)
	}

	// Parse the TimeStampResp to extract the TimeStampToken.
	var tsResp timeStampResp
	if _, err := asn1.Unmarshal(body, &tsResp); err != nil {
		return nil, fmt.Errorf("unmarshal timestamp response: %w", err)
	}

	// Status 0 = granted, 1 = grantedWithMods.
	if tsResp.Status.Status > 1 {
		return nil, fmt.Errorf("TSA rejected request with status %d", tsResp.Status.Status)
	}

	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("TSA response contains no timestamp token")
	}

	return tsResp.TimeStampToken.FullBytes, nil
}

// extractSignatureValue parses a PKCS#7 DER structure and returns the
// EncryptedDigest (signature value) from the first SignerInfo.
//
// PKCS#7 ContentInfo structure:
//
//	SEQUENCE {
//	  OID (signedData)
//	  [0] EXPLICIT SEQUENCE {    -- SignedData
//	    INTEGER (version)
//	    SET { ... }              -- digestAlgorithms
//	    SEQUENCE { ... }         -- contentInfo
//	    [0] IMPLICIT ...         -- certificates (optional)
//	    [1] IMPLICIT ...         -- crls (optional)
//	    SET {                    -- signerInfos
//	      SEQUENCE {             -- first SignerInfo
//	        INTEGER (version)
//	        SEQUENCE { ... }     -- issuerAndSerialNumber
//	        SEQUENCE { ... }     -- digestAlgorithm
//	        [0] ...              -- authenticatedAttributes (optional)
//	        SEQUENCE { ... }     -- digestEncryptionAlgorithm
//	        OCTET STRING         -- EncryptedDigest (THIS IS WHAT WE WANT)
//	        [1] ...              -- unauthenticatedAttributes (optional)
//	      }
//	    }
//	  }
//	}
func extractSignatureValue(pkcs7DER []byte) ([]byte, error) {
	// Parse ContentInfo.
	var contentInfo asn1.RawValue
	if _, err := asn1.Unmarshal(pkcs7DER, &contentInfo); err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	if !contentInfo.IsCompound {
		return nil, fmt.Errorf("ContentInfo is not compound")
	}

	// Walk the ContentInfo SEQUENCE to find [0] EXPLICIT (the SignedData).
	rest := contentInfo.Bytes
	// Skip the OID.
	var oid asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &oid)
	// Next is [0] EXPLICIT containing SignedData.
	var signedDataWrapper asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &signedDataWrapper); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData wrapper: %w", err)
	}

	// Parse SignedData SEQUENCE.
	var signedData asn1.RawValue
	if _, err := asn1.Unmarshal(signedDataWrapper.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}

	// Walk SignedData fields to find signerInfos (the last SET in the SEQUENCE).
	rest = signedData.Bytes
	var lastSet asn1.RawValue
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			break
		}
		// signerInfos is a SET (tag 17).
		if field.Tag == asn1.TagSet && field.Class == asn1.ClassUniversal {
			lastSet = field
		}
	}

	if len(lastSet.Bytes) == 0 {
		return nil, fmt.Errorf("signerInfos SET not found")
	}

	// Parse the first SignerInfo SEQUENCE inside the SET.
	var signerInfo asn1.RawValue
	if _, err := asn1.Unmarshal(lastSet.Bytes, &signerInfo); err != nil {
		return nil, fmt.Errorf("unmarshal first SignerInfo: %w", err)
	}

	// Walk SignerInfo fields. The EncryptedDigest is an OCTET STRING
	// that comes after the digestEncryptionAlgorithm SEQUENCE.
	// Fields: version(INT), issuerAndSerial(SEQ), digestAlg(SEQ),
	//         [0] authAttrs(optional), digestEncAlg(SEQ), encDigest(OCTET STRING)
	rest = signerInfo.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			break
		}
		// EncryptedDigest is an OCTET STRING (tag 4, universal class).
		if field.Tag == asn1.TagOctetString && field.Class == asn1.ClassUniversal && len(field.Bytes) > 0 {
			return field.Bytes, nil
		}
	}

	return nil, fmt.Errorf("EncryptedDigest not found in SignerInfo")
}
