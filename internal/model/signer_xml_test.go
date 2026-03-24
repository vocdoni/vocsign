package model

import (
	"encoding/xml"
	"strings"
	"testing"
)

func testRequest(title string) *SignRequest {
	return &SignRequest{
		RequestID: "REQ-12345",
		Proposal: Proposal{
			Title: title,
		},
	}
}

func testSignant() Signant {
	return Signant{
		Nom:             "Joan",
		Cognom1:         "Garcia",
		Cognom2:         "Lopez",
		DataNaixement:   "1990-05-15",
		TipusIdentifica: "DNI",
		NumIdentifica:   "12345678A",
	}
}

func TestGenerateILPXML_ValidOutput(t *testing.T) {
	req := testRequest("Test Proposal")
	data := testSignant()

	out, err := GenerateILPXML(req, data)
	if err != nil {
		t.Fatalf("GenerateILPXML returned error: %v", err)
	}
	s := string(out)

	// Must start with XML header
	if !strings.HasPrefix(s, xml.Header) {
		t.Fatal("output does not start with XML header")
	}

	// Must contain all signer fields
	for _, field := range []string{
		"<Nom>Joan</Nom>",
		"<Cognom1>Garcia</Cognom1>",
		"<Cognom2>Lopez</Cognom2>",
		"<DataNaixement>1990-05-15</DataNaixement>",
		"<TipusIdentificador>DNI</TipusIdentificador>",
		"<NumeroIdentificador>12345678A</NumeroIdentificador>",
	} {
		if !strings.Contains(s, field) {
			t.Errorf("output missing expected field %q", field)
		}
	}

	// Must contain root element with version attribute
	if !strings.Contains(s, `<SignaturaILP versio="1.0">`) {
		t.Error("output missing root element with versio attribute")
	}
}

func TestGenerateILPXML_ContainsProposalTitle(t *testing.T) {
	title := "Iniciativa Legislativa Popular de prova"
	req := testRequest(title)
	data := testSignant()

	out, err := GenerateILPXML(req, data)
	if err != nil {
		t.Fatalf("GenerateILPXML returned error: %v", err)
	}

	expected := "<Titol>" + title + "</Titol>"
	if !strings.Contains(string(out), expected) {
		t.Errorf("output does not contain proposal title; want %q in output", expected)
	}
}

func TestGenerateILPXML_ContainsRequestID(t *testing.T) {
	req := testRequest("Some Title")
	data := testSignant()

	out, err := GenerateILPXML(req, data)
	if err != nil {
		t.Fatalf("GenerateILPXML returned error: %v", err)
	}

	expected := "<Codi>" + req.RequestID + "</Codi>"
	if !strings.Contains(string(out), expected) {
		t.Errorf("output does not contain RequestID as Codi; want %q in output", expected)
	}
}

func TestGenerateILPXML_RoundTrip(t *testing.T) {
	req := testRequest("Round Trip Title")
	data := testSignant()

	out, err := GenerateILPXML(req, data)
	if err != nil {
		t.Fatalf("GenerateILPXML returned error: %v", err)
	}

	var got ILPSignerXML
	if err := xml.Unmarshal(out, &got); err != nil {
		t.Fatalf("xml.Unmarshal returned error: %v", err)
	}

	if got.Versio != "1.0" {
		t.Errorf("Versio = %q, want %q", got.Versio, "1.0")
	}
	if got.ILP.Titol != req.Proposal.Title {
		t.Errorf("ILP.Titol = %q, want %q", got.ILP.Titol, req.Proposal.Title)
	}
	if got.ILP.Codi != req.RequestID {
		t.Errorf("ILP.Codi = %q, want %q", got.ILP.Codi, req.RequestID)
	}
	if got.Signant.Nom != data.Nom {
		t.Errorf("Signant.Nom = %q, want %q", got.Signant.Nom, data.Nom)
	}
	if got.Signant.Cognom1 != data.Cognom1 {
		t.Errorf("Signant.Cognom1 = %q, want %q", got.Signant.Cognom1, data.Cognom1)
	}
	if got.Signant.Cognom2 != data.Cognom2 {
		t.Errorf("Signant.Cognom2 = %q, want %q", got.Signant.Cognom2, data.Cognom2)
	}
	if got.Signant.DataNaixement != data.DataNaixement {
		t.Errorf("Signant.DataNaixement = %q, want %q", got.Signant.DataNaixement, data.DataNaixement)
	}
	if got.Signant.TipusIdentifica != data.TipusIdentifica {
		t.Errorf("Signant.TipusIdentifica = %q, want %q", got.Signant.TipusIdentifica, data.TipusIdentifica)
	}
	if got.Signant.NumIdentifica != data.NumIdentifica {
		t.Errorf("Signant.NumIdentifica = %q, want %q", got.Signant.NumIdentifica, data.NumIdentifica)
	}
}

func TestGenerateILPXML_SpecialCharacters(t *testing.T) {
	title := "Law & Order <Section> \"Test\""
	req := testRequest(title)
	data := testSignant()

	out, err := GenerateILPXML(req, data)
	if err != nil {
		t.Fatalf("GenerateILPXML returned error: %v", err)
	}
	s := string(out)

	// Special characters must be escaped in the raw XML
	if strings.Contains(s, "&<") || strings.Contains(s, "& ") {
		// The ampersand should be escaped as &amp;
		t.Error("ampersand not properly escaped")
	}
	if !strings.Contains(s, "&amp;") {
		t.Error("expected &amp; escape for & character")
	}
	if !strings.Contains(s, "&lt;") {
		t.Error("expected &lt; escape for < character")
	}
	// Verify round-trip preserves special characters
	var got ILPSignerXML
	if err := xml.Unmarshal(out, &got); err != nil {
		t.Fatalf("xml.Unmarshal returned error: %v", err)
	}
	if got.ILP.Titol != title {
		t.Errorf("round-trip title = %q, want %q", got.ILP.Titol, title)
	}
}
