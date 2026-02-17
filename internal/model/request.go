package model

type SignRequest struct {
	Version            string              `json:"version"`
	RequestID          string              `json:"requestId"`
	IssuedAt           string              `json:"issuedAt"`
	ExpiresAt          string              `json:"expiresAt"`
	Nonce              string              `json:"nonce"`
	Proposal           Proposal            `json:"proposal"`
	Callback           Callback            `json:"callback"`
	Organizer          Organizer           `json:"organizer"`
	OrganizerSignature *OrganizerSignature `json:"organizerSignature,omitempty"` // Pointer to allow omitting in canonical encoding if needed
	Policy             *SignPolicy         `json:"policy,omitempty"`
}

type Proposal struct {
	Title          string   `json:"title"`
	Promoter       string   `json:"promoter"`
	Jurisdiction   string   `json:"jurisdiction"`
	Summary        string   `json:"summary"`
	LegalStatement string   `json:"legalStatement"` // Clear statement of what is being signed
	FullText       FullText `json:"fullText"`
}

type FullText struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Callback struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

type Organizer struct {
	KID       string `json:"kid"`
	JWKSetURL string `json:"jwkSetUrl"`
}

type OrganizerSignature struct {
	Format string `json:"format"`
	Value  string `json:"value"`
}

type SignPolicy struct {
	Mode    string `json:"mode"`
	OID     string `json:"oid,omitempty"`
	HashAlg string `json:"hashAlg,omitempty"`
	Hash    string `json:"hash,omitempty"`
	URI     string `json:"uri,omitempty"`
}

// Payload to be signed
type SignPayload struct {
	Version      string          `json:"v"`
	RequestID    string          `json:"requestId"`
	Nonce        string          `json:"nonce"`
	IssuedAt     string          `json:"issuedAt"`
	ExpiresAt    string          `json:"expiresAt"`
	Proposal     PayloadProposal `json:"proposal"`
	CallbackHost string          `json:"callbackHost"`
	Policy       *SignPolicy     `json:"policy,omitempty"`
}

type PayloadProposal struct {
	Title          string `json:"title"`
	Promoter       string `json:"promoter"`
	Jurisdiction   string `json:"jurisdiction"`
	FullTextSHA256 string `json:"fullTextSha256"`
}
