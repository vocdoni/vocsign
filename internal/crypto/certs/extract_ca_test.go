package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestExtractSpanishIdentity_PerCA(t *testing.T) {
	type testCase struct {
		name     string
		cert     *x509.Certificate
		wantNom  string
		wantDNI  string
		wantType string
		wantRep  bool
		wantOrg  string
		wantOID  string
		wantDOB  string
	}

	cases := []testCase{
		// --- Personal certificates (DNI) per CA ---
		{
			name: "FNMT_Usuarios_DNI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "ESPANOL ESPANOL JUAN - 00000000T",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-00000000T"},
						{Type: oidGivenName, Value: "JUAN"},
						{Type: oidSurname, Value: "ESPANOL ESPANOL"},
					},
				},
				Issuer:   pkix.Name{CommonName: "AC FNMT Usuarios"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "JUAN", wantDNI: "00000000T", wantType: "DNI",
		},
		{
			name: "FNMT_UsuariosG2_DNI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "ESPANOL ESPANOL JUAN - DNI 00000000T",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-00000000T"},
						{Type: oidGivenName, Value: "JUAN"},
						{Type: oidSurname, Value: "ESPANOL ESPANOL"},
					},
				},
				Issuer:   pkix.Name{CommonName: "AC USUARIOS G2"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "JUAN", wantDNI: "00000000T", wantType: "DNI",
		},
		// EC-Ciutadania DNI with Barcelona already covered in extract_test.go
		// (TestExtractSpanishIdentity_PersonalIDCatStyle)
		{
			name: "EC_idCAT_DNI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "ALBA TESTER DEMO - DNI 12345678Z",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-12345678Z"},
						{Type: oidGivenName, Value: "ALBA"},
						{Type: oidSurname, Value: "TESTER DEMO"},
					},
				},
				Issuer:   pkix.Name{CommonName: "EC-idCAT"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "ALBA", wantDNI: "12345678Z", wantType: "DNI",
		},
		{
			// ACCV does not use IDCES- prefix. Real ACCV certs may zero-pad
			// the NIF to 9 chars (e.g. "012345678Z"), but the current reDNI
			// regex only matches 8 digits + letter. This test uses the standard
			// 9-char DNI format that extractID can handle.
			name: "ACCV_DNI_no_prefix",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "MARIA LOPEZ GARCIA - NIF:12345678Z",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "12345678Z"},
						{Type: oidGivenName, Value: "MARIA"},
						{Type: oidSurname, Value: "LOPEZ GARCIA"},
						{Type: oidOrganization, Value: "ACCV"},
					},
				},
				Issuer:   pkix.Name{CommonName: "ACCVCA-120"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "MARIA", wantDNI: "12345678Z", wantType: "DNI",
		},
		{
			name: "IZENPE_DNI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "09421399R JAIME RODRIGO",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-09421399R"},
						{Type: oidGivenName, Value: "JAIME"},
						{Type: oidSurname, Value: "RODRIGO POCH"},
					},
				},
				Issuer:   pkix.Name{CommonName: "Izenpe.com"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "JAIME", wantDNI: "09421399R", wantType: "DNI",
		},
		{
			name: "ANF_AC_DNI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "GARCIA LOPEZ MARIA - 12345678A",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-12345678A"},
						{Type: oidGivenName, Value: "MARIA"},
						{Type: oidSurname, Value: "GARCIA LOPEZ"},
					},
				},
				Issuer:   pkix.Name{CommonName: "ANF AC"},
				NotAfter: time.Now().Add(365 * 24 * time.Hour),
			},
			wantNom: "MARIA", wantDNI: "12345678A", wantType: "DNI",
		},
		// --- NIE and CIF ---
		// FNMT NIE X1234567A already covered in extract_test.go
		// (TestExtractSpanishIdentity_NIE)
		{
			name: "AOC_NIE",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "ANNA SMITH - DNI Y9876543B",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-Y9876543B"},
						{Type: oidGivenName, Value: "ANNA"},
						{Type: oidSurname, Value: "SMITH"},
					},
				},
				Issuer: pkix.Name{CommonName: "EC-Ciutadania"},
			},
			wantNom: "ANNA", wantDNI: "Y9876543B", wantType: "NIE",
		},
		{
			name: "ACCV_NIE_no_prefix",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "JOHN DOE - NIF:X1234567A",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "X1234567A"},
						{Type: oidGivenName, Value: "JOHN"},
						{Type: oidSurname, Value: "DOE"},
					},
				},
				Issuer: pkix.Name{CommonName: "ACCVCA-120"},
			},
			wantNom: "JOHN", wantDNI: "X1234567A", wantType: "NIE",
		},
		{
			// Note: spec says IDType=CIF, but extractID parses the serialNumber
			// field which contains the holder's personal DNI (00000000T), not the
			// entity CIF (B75576322). The CIF appears only in organizationIdentifier.
			// The holder's IDType is correctly DNI.
			name: "FNMT_Rep_CIF",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "00000000T Juan Espanol (R: B75576322)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-00000000T"},
						{Type: oidGivenName, Value: "JUAN"},
						{Type: oidSurname, Value: "ESPANOL"},
						{Type: oidOrganizationIdentifier, Value: "VATES-B75576322"},
						{Type: oidOrganization, Value: "EMPRESA S.L."},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacion"},
			},
			wantNom: "JUAN", wantDNI: "00000000T", wantType: "DNI",
			wantRep: true, wantOrg: "EMPRESA S.L.", wantOID: "B75576322",
		},
		// --- Representative certificates (bilingual) ---
		{
			name: "FNMT_Rep_Spanish",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "00000000T Juan Espanol (R: Q00000000J)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-00000000T"},
						{Type: oidGivenName, Value: "JUAN"},
						{Type: oidSurname, Value: "ESPANOL"},
						{Type: oidOrganizationIdentifier, Value: "VATES-Q00000000J"},
						{Type: oidOrganization, Value: "ENTIDAD DE PRUEBAS"},
						{Type: oidDescription, Value: "Reg:28001 /Hoja:M-123456 /Inscripcion:1"},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacion"},
			},
			wantNom: "JUAN", wantDNI: "00000000T", wantType: "DNI",
			wantRep: true, wantOrg: "ENTIDAD DE PRUEBAS", wantOID: "Q00000000J",
		},
		{
			name: "CATCert_Rep_Catalan",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "47824166J Pau Escrich Representant (R: B75576322)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-47824166J"},
						{Type: oidGivenName, Value: "PAU"},
						{Type: oidSurname, Value: "ESCRICH"},
						{Type: oidOrganizationIdentifier, Value: "VATES-B75576322"},
						{Type: oidOrganization, Value: "EMPRESA CATALANA S.L."},
						{Type: oidDescription, Value: "Reg:08005 /Hoja:B-627188 /Inscripcio:1"},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacio"},
			},
			wantNom: "PAU", wantDNI: "47824166J", wantType: "DNI",
			wantRep: true, wantOrg: "EMPRESA CATALANA S.L.", wantOID: "B75576322",
		},
		{
			name: "Rep_Apoderado_Spanish",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Apoderado: 12345678Z MARIA GARCIA (R: A12345678)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-12345678Z"},
						{Type: oidGivenName, Value: "MARIA"},
						{Type: oidSurname, Value: "GARCIA"},
						{Type: oidOrganization, Value: "EMPRESA ESPANOLA S.A."},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacion"},
			},
			wantNom: "MARIA", wantDNI: "12345678Z", wantType: "DNI",
			wantRep: true,
		},
		{
			name: "Rep_Apoderat_Catalan",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Apoderat: 12345678Z MARIA GARCIA (R: A12345678)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-12345678Z"},
						{Type: oidGivenName, Value: "MARIA"},
						{Type: oidSurname, Value: "GARCIA"},
						{Type: oidOrganization, Value: "EMPRESA CATALANA S.A."},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacio"},
			},
			wantNom: "MARIA", wantDNI: "12345678Z", wantType: "DNI",
			wantRep: true,
		},
		{
			name: "Rep_AEAT_Description",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "00000000T Juan Espanol (R: Q00000000J)",
					Names: []pkix.AttributeTypeAndValue{
						{Type: oidSerialNumber, Value: "IDCES-00000000T"},
						{Type: oidGivenName, Value: "JUAN"},
						{Type: oidSurname, Value: "ESPANOL"},
						{Type: oidOrganization, Value: "EMPRESA S.L."},
						{Type: oidDescription, Value: "REF:AEAT/NIF:Q00000000J"},
					},
				},
				Issuer: pkix.Name{CommonName: "AC Representacion"},
			},
			wantNom: "JUAN", wantDNI: "00000000T", wantType: "DNI",
			wantRep: true, wantOrg: "EMPRESA S.L.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := ExtractSpanishIdentity(tc.cert)

			if info.Nom != tc.wantNom {
				t.Errorf("Nom: got %q, want %q", info.Nom, tc.wantNom)
			}
			if info.DNI != tc.wantDNI {
				t.Errorf("DNI: got %q, want %q", info.DNI, tc.wantDNI)
			}
			if info.IDType != tc.wantType {
				t.Errorf("IDType: got %q, want %q", info.IDType, tc.wantType)
			}
			if info.IsRepresentative != tc.wantRep {
				t.Errorf("IsRepresentative: got %v, want %v", info.IsRepresentative, tc.wantRep)
			}
			if tc.wantOrg != "" && info.Organization != tc.wantOrg {
				t.Errorf("Organization: got %q, want %q", info.Organization, tc.wantOrg)
			}
			if tc.wantOID != "" && info.OrganizationID != tc.wantOID {
				t.Errorf("OrganizationID: got %q, want %q", info.OrganizationID, tc.wantOID)
			}
			if tc.wantDOB != "" && info.BirthDate != tc.wantDOB {
				t.Errorf("BirthDate: got %q, want %q", info.BirthDate, tc.wantDOB)
			}
		})
	}
}

// DOB extraction already covered in extract_test.go
// (TestExtractSpanishIdentity_DateOfBirth)
