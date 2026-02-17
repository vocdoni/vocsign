package model

type SignResponse struct {
	Version                string       `json:"version"`
	RequestID              string       `json:"requestId"`
	Nonce                  string       `json:"nonce"`
	SignedAt               string       `json:"signedAt"`
	PayloadCanonicalSHA256 string       `json:"payloadCanonicalSha256"`
	SignatureFormat        string       `json:"signatureFormat"`
	SignatureDerBase64     string       `json:"signatureDerBase64"`
	SignerCertPEM          string       `json:"signerCertPem"`
	ChainPEM               []string     `json:"chainPem"`
	SignerXMLBase64        string       `json:"signerXmlBase64,omitempty"` // Legally required XML
	Client                 ClientInfo   `json:"client"`
}

type ClientInfo struct {
	App     string `json:"app"`
	Version string `json:"version"`
	OS      string `json:"os"`
}

type SubmitReceipt struct {
	Status     string `json:"status"`
	ReceiptID  string `json:"receiptId"`
	ReceivedAt string `json:"receivedAt"`
}
