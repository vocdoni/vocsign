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
	Organization     string
	OrganizationID   string
	IsRepresentative bool
	RawSubject       string
	Issuer           string
	ValidUntil       string
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
			if id := extractID(val); id != "" {
				info.DNI = id
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
		info.DNI = extractID(cn)
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

	return info
}

func extractID(s string) string {
	v := strings.ToUpper(normalizeSpace(s))
	v = strings.TrimPrefix(v, "IDCES-")
	v = strings.TrimPrefix(v, "IDESP-")
	if m := reID.FindStringSubmatch(v); len(m) > 1 {
		v = m[1]
	}
	switch {
	case reDNI.MatchString(v):
		return reDNI.FindString(v)
	case reNIE.MatchString(v):
		return reNIE.FindString(v)
	case reCIF.MatchString(v):
		return reCIF.FindString(v)
	default:
		return ""
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
