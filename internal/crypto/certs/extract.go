package certs

import (
	"crypto/x509"
	"encoding/asn1"
	"regexp"
	"strings"
)

var (
	oidGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidOrganization           = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidDescription            = asn1.ObjectIdentifier{2, 5, 4, 13}
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

	oidSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidDateOfBirth                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
)

var (
	// Spanish personal identifiers.
	reDNI = regexp.MustCompile(`\b\d{8}[A-Z]\b`)
	reNIE = regexp.MustCompile(`\b[XYZ]\d{7}[A-Z]\b`)
	// Common CIF/NIF legal-entity format.
	reCIF = regexp.MustCompile(`\b[ABCDEFGHJNPQRSUVW]\d{7}[0-9A-J]\b`)
	reID  = regexp.MustCompile(`(?i)\b(?:DNI|NIE)\s*[:\-]?\s*([A-Z0-9]{8,9})\b`)
	reRep = regexp.MustCompile(`(?i)\(\s*R:\s*([A-Z]\d{7}[0-9A-J])\s*\)`)
)

type ExtractedInfo struct {
	Nom              string
	Cognoms          []string
	DNI              string
	IDType           string
	Organization     string
	OrganizationID   string
	IsRepresentative bool
	RawSubject       string
	Issuer           string
	ValidUntil       string
	BirthDate        string // YYYY-MM-DD, from Subject Directory Attributes if present
}

func ExtractSpanishIdentity(cert *x509.Certificate) ExtractedInfo {
	info := ExtractedInfo{
		RawSubject: cert.Subject.String(),
		Issuer:     cert.Issuer.CommonName,
		ValidUntil: cert.NotAfter.Format("2006-01-02"),
	}

	var hasPersonalAttrs bool
	var hasSubjectOrg bool
	var hasSubjectOrgID bool
	var hasRepDescription bool
	for _, name := range cert.Subject.Names {
		val, ok := name.Value.(string)
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if name.Type.Equal(oidGivenName) {
			info.Nom = val
			if info.Nom != "" {
				hasPersonalAttrs = true
			}
		} else if name.Type.Equal(oidSurname) {
			info.Cognoms = splitWords(val)
			if len(info.Cognoms) > 0 {
				hasPersonalAttrs = true
			}
		} else if name.Type.Equal(oidSerialNumber) {
			if id, idType := extractID(val); id != "" {
				info.DNI = id
				info.IDType = idType
				if isPersonalID(id) {
					hasPersonalAttrs = true
				}
			}
		} else if name.Type.Equal(oidOrganization) {
			info.Organization = normalizeSpace(val)
			hasSubjectOrg = info.Organization != ""
		} else if name.Type.Equal(oidOrganizationIdentifier) {
			info.OrganizationID = extractOrgID(val)
			hasSubjectOrgID = info.OrganizationID != ""
		} else if name.Type.Equal(oidDescription) {
			desc := strings.ToUpper(normalizeSpace(val))
			if strings.Contains(desc, "REG:") || strings.Contains(desc, "REF:AEAT") || strings.Contains(desc, "INSCRIPCI") {
				hasRepDescription = true
			}
		}
	}

	// Fallbacks from CN.
	cn := normalizeSpace(cert.Subject.CommonName)
	if info.OrganizationID == "" {
		info.OrganizationID = extractRepresentativeID(cn)
	}
	if info.DNI == "" {
		id, idType := extractID(cn)
		info.DNI = id
		info.IDType = idType
	}
	if info.Nom == "" || len(info.Cognoms) == 0 {
		namePart := cn
		if idx := strings.Index(namePart, " - "); idx >= 0 {
			namePart = namePart[:idx]
		}
		if idx := strings.Index(strings.ToUpper(namePart), " DNI "); idx >= 0 {
			namePart = namePart[:idx]
		}
		namePart = normalizeSpace(namePart)
		if namePart != "" {
			parts := splitWords(namePart)
			if info.Nom == "" && len(parts) > 0 {
				info.Nom = parts[0]
			}
			if len(info.Cognoms) == 0 && len(parts) >= 2 {
				info.Cognoms = parts[1:]
			}
		}
	}

	hasPersonalIdentity := hasPersonalAttrs || isPersonalID(info.DNI)
	hasRepCN := looksRepresentativeCN(cn) || extractRepresentativeID(cn) != ""
	issuerRep := looksRepresentativeIssuer(cert.Issuer.CommonName)

	// Representative if strong representative markers are present, even if personal holder
	// attributes (GN/SN/DNI) are also present.
	info.IsRepresentative = hasSubjectOrgID || hasRepCN || (hasSubjectOrg && issuerRep) || hasRepDescription || (!hasPersonalIdentity && hasSubjectOrg)

	// Personal certs sometimes carry issuer-related organization labels in subject fields.
	if !info.IsRepresentative && hasPersonalIdentity {
		info.Organization = ""
		info.OrganizationID = ""
	}

	info.BirthDate = extractDateOfBirth(cert)

	return info
}

// extractDateOfBirth parses the dateOfBirth from the Subject Directory
// Attributes extension (OID 2.5.29.9) if present. Returns "" if not found.
func extractDateOfBirth(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectDirectoryAttributes) {
			continue
		}
		var attrs []asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &attrs)
		if err != nil || len(rest) > 0 {
			return ""
		}
		for _, rawAttr := range attrs {
			var attrSeq asn1.RawValue
			if _, err := asn1.Unmarshal(rawAttr.FullBytes, &attrSeq); err != nil {
				continue
			}
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(attrSeq.Bytes, &oid)
			if err != nil || !oid.Equal(oidDateOfBirth) {
				continue
			}
			var setValue asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &setValue); err != nil {
				continue
			}
			var gt asn1.RawValue
			if _, err := asn1.Unmarshal(setValue.Bytes, &gt); err != nil {
				continue
			}
			s := string(gt.Bytes)
			if len(s) >= 8 {
				return s[0:4] + "-" + s[4:6] + "-" + s[6:8]
			}
		}
	}
	return ""
}

func extractID(s string) (id string, idType string) {
	v := strings.ToUpper(normalizeSpace(s))
	v = strings.TrimPrefix(v, "IDCES-")
	v = strings.TrimPrefix(v, "IDESP-")
	if m := reID.FindStringSubmatch(v); len(m) > 1 {
		v = m[1]
	}
	switch {
	case reDNI.MatchString(v):
		return reDNI.FindString(v), "DNI"
	case reNIE.MatchString(v):
		return reNIE.FindString(v), "NIE"
	case reCIF.MatchString(v):
		return reCIF.FindString(v), "CIF"
	default:
		return "", ""
	}
}

func isPersonalID(id string) bool {
	return reDNI.MatchString(id) || reNIE.MatchString(id)
}

func looksRepresentativeCN(cn string) bool {
	cn = strings.ToUpper(cn)
	return strings.Contains(cn, "REPRESENT") || strings.Contains(cn, "APODERAD") || strings.Contains(cn, "(R:")
}

func looksRepresentativeIssuer(issuerCN string) bool {
	cn := strings.ToUpper(normalizeSpace(issuerCN))
	return strings.Contains(cn, "REPRESENT")
}

func extractRepresentativeID(s string) string {
	m := reRep.FindStringSubmatch(strings.ToUpper(s))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func extractOrgID(s string) string {
	v := strings.ToUpper(normalizeSpace(s))
	v = strings.TrimPrefix(v, "VATES-")
	if reCIF.MatchString(v) {
		return reCIF.FindString(v)
	}
	return v
}

func splitWords(s string) []string {
	s = normalizeSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}
