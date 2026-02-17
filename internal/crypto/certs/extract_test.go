package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestExtractSpanishIdentity_PersonalIDCatStyle(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "PAU ESCRICH GARCIA  - DNI 47824166J",
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidGivenName, Value: "PAU"},
				{Type: oidSurname, Value: "ESCRICH GARCIA"},
				{Type: oidSerialNumber, Value: "IDCES-47824166J"},
			},
		},
		Issuer: pkix.Name{
			CommonName:   "EC-Ciutadania",
			Organization: []string{"CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA"},
		},
		NotAfter: time.Date(2026, 2, 22, 9, 10, 11, 0, time.UTC),
	}

	info := ExtractSpanishIdentity(cert)
	if info.IsRepresentative {
		t.Fatal("expected personal certificate, got representative")
	}
	if info.Organization != "" {
		t.Fatalf("expected empty organization for personal cert, got %q", info.Organization)
	}
	if info.Nom != "PAU" {
		t.Fatalf("unexpected given name: %q", info.Nom)
	}
	if info.DNI != "47824166J" {
		t.Fatalf("unexpected DNI: %q", info.DNI)
	}
}

func TestExtractSpanishIdentity_RepresentativeWithoutPersonalMarkers(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "47824166J PAU ESCRICH (R: B75576322)",
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidSerialNumber, Value: "IDCES-47824166J"},
				{Type: oidGivenName, Value: "PAU"},
				{Type: oidSurname, Value: "ESCRICH GARCIA"},
				{Type: oidOrganizationIdentifier, Value: "VATES-B75576322"},
				{Type: oidOrganization, Value: "SYNERGIZE S.L."},
				{Type: oidDescription, Value: "Reg:08005 /Hoja:B-627188 /IRUS:0 /Fecha:11/01/2025 /Inscripción:1"},
			},
		},
		Issuer: pkix.Name{CommonName: "AC Representación"},
	}

	info := ExtractSpanishIdentity(cert)
	if !info.IsRepresentative {
		t.Fatal("expected representative certificate")
	}
	if info.Organization != "SYNERGIZE S.L." {
		t.Fatalf("unexpected organization: %q", info.Organization)
	}
	if info.OrganizationID != "B75576322" {
		t.Fatalf("unexpected organization id: %q", info.OrganizationID)
	}
	if info.DNI != "47824166J" {
		t.Fatalf("unexpected DNI: %q", info.DNI)
	}
}

func TestExtractSpanishIdentity_PersonalFNMTUsuarios(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "ESCRICH GARCIA PAU - 47824166J",
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidSerialNumber, Value: "IDCES-47824166J"},
				{Type: oidGivenName, Value: "PAU"},
				{Type: oidSurname, Value: "ESCRICH GARCIA"},
			},
		},
		Issuer: pkix.Name{CommonName: "AC FNMT Usuarios"},
	}

	info := ExtractSpanishIdentity(cert)
	if info.IsRepresentative {
		t.Fatal("expected personal certificate")
	}
	if info.DNI != "47824166J" {
		t.Fatalf("unexpected DNI: %q", info.DNI)
	}
}
