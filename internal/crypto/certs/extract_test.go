package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	if info.IDType != "DNI" {
		t.Fatalf("expected IDType %q, got %q", "DNI", info.IDType)
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
	if info.IDType != "DNI" {
		t.Fatalf("expected IDType %q, got %q", "DNI", info.IDType)
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
	if info.IDType != "DNI" {
		t.Fatalf("expected IDType %q, got %q", "DNI", info.IDType)
	}
}

func TestExtractSpanishIdentity_NIE(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "GARCIA LOPEZ MARIA - NIE X1234567A",
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidSerialNumber, Value: "IDCES-X1234567A"},
				{Type: oidGivenName, Value: "MARIA"},
				{Type: oidSurname, Value: "GARCIA LOPEZ"},
			},
		},
		Issuer:   pkix.Name{CommonName: "AC FNMT Usuarios"},
		NotAfter: time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC),
	}

	info := ExtractSpanishIdentity(cert)
	if info.IsRepresentative {
		t.Fatal("expected personal certificate, got representative")
	}
	if info.DNI != "X1234567A" {
		t.Fatalf("unexpected DNI: %q", info.DNI)
	}
	if info.IDType != "NIE" {
		t.Fatalf("expected IDType %q, got %q", "NIE", info.IDType)
	}
	if info.Nom != "MARIA" {
		t.Fatalf("unexpected given name: %q", info.Nom)
	}
}

func TestExtractSpanishIdentity_DateOfBirth(t *testing.T) {
	sdaValue := buildTestSDA(t, "19900515")
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "PAU ESCRICH GARCIA - DNI 47824166J",
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidGivenName, Value: "PAU"},
				{Type: oidSurname, Value: "ESCRICH GARCIA"},
				{Type: oidSerialNumber, Value: "IDCES-47824166J"},
			},
		},
		Issuer: pkix.Name{CommonName: "AC FNMT Usuarios"},
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 9},
				Value: sdaValue,
			},
		},
	}
	info := ExtractSpanishIdentity(cert)
	if info.BirthDate != "1990-05-15" {
		t.Fatalf("expected BirthDate %q, got %q", "1990-05-15", info.BirthDate)
	}
}

func buildTestSDA(t *testing.T, dateYYYYMMDD string) []byte {
	t.Helper()
	dobOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
	genTime := dateYYYYMMDD + "000000Z"
	gtBytes, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: 24, Bytes: []byte(genTime),
	})
	if err != nil {
		t.Fatal(err)
	}
	setBytes, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: 17, IsCompound: true, Bytes: gtBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	type attribute struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	result, err := asn1.Marshal([]attribute{{
		Type: dobOID, Value: asn1.RawValue{FullBytes: setBytes},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
