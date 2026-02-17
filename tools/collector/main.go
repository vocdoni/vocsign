package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vocdoni/gofirma/vocsign/internal/canon"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/smallstep/pkcs7"
)

type ProposalState struct {
	Request    model.SignRequest
	Signatures int
	Audit      []model.SignResponse
	mu         sync.Mutex
}

var (
	organizerKey *rsa.PrivateKey
	organizerPub *rsa.PublicKey
	kid          = "vocsign-key-1"
	
	proposals = make(map[string]*ProposalState)
	pMu       sync.Mutex

	port   int
	domain string
)

func main() {
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&domain, "domain", "localhost:8080", "Domain for proposal links")
	flag.Parse()

	var err error
	organizerKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	organizerPub = &organizerKey.PublicKey

	// Initialize 3 realistic proposals
	initProposals()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/jwks.json", handleJWKS)
	http.HandleFunc("/request/", handleGetRequest)
	http.HandleFunc("/callback/", handleCallback)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("VocSign Collector listening on %s (domain: %s)", addr, domain)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func initProposals() {
	addProposal("ILP-2026-HABITATGE", "PROPOSICIÓ DE LLEI DE MESURES URGENTS PER A L'HABITATGE DIGNE", 
		"Comissió Promotora de la ILP per l'Habitatge Digne", 
		"Aquesta iniciativa proposa regular els preus del lloguer, augmentar el parc d'habitatge social i garantir el dret a un sostre digne.")
	
	addProposal("ILP-2026-EDUCACIO", "LLEI DE FINANÇAMENT DEL SISTEMA EDUCATIU PÚBLIC (6%)", 
		"Plataforma per una Educació Pública de Qualitat", 
		"Garantir per llei un mínim del 6% del PIB per a l'educació pública a Catalunya per revertir les retallades i millorar ràtios.")
	
	addProposal("ILP-2026-CLIMA", "PROPOSICIÓ DE LLEI DE PROTECCIÓ DELS ESPAIS NATURALS LITORALS", 
		"SOS Costa Catalana", 
		"Protecció efectiva dels darrers espais verds a la costa, moratòria de noves urbanitzacions i plans de restauració d'ecosistemes.")
}

func addProposal(id, title, promoter, summary string) {
	baseURL := domain
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	req := model.SignRequest{
		Version:   "1.0",
		RequestID: id,
		IssuedAt:  time.Now().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		Nonce:     base64.StdEncoding.EncodeToString([]byte(uuid.New().String())),
		Proposal: model.Proposal{
			Title:        title,
			Promoter:     promoter,
			Jurisdiction: "Catalunya",
			Summary:      summary,
			LegalStatement: "Mitjançant la meva signatura electrònica, dono el meu suport a la present Proposició de Llei, d'acord amb el que estableix la Llei 1/2006, de 16 de febrer.",
			FullText: model.FullText{
				URL:    "https://vocdoni.io/docs/ilp-example.pdf",
				SHA256: "Gvj/Kk/Jc+j8+j8+j8+j8+j8+j8+j8+j8+j8+j8+j88=",
			},
		},
		Callback: model.Callback{
			URL:    fmt.Sprintf("%s/callback/%s", baseURL, id),
			Method: "POST",
		},
		Organizer: model.Organizer{
			KID:       kid,
			JWKSetURL: fmt.Sprintf("%s/jwks.json", baseURL),
		},
		Policy: &model.SignPolicy{
			Mode:    "required",
			OID:     "1.3.6.1.4.1.47443.8.1.1",
			HashAlg: "sha256",
			Hash:    "Gvj/Kk/Jc+j8+j8+j8+j8+j8+j8+j8+j8+j8+j8+j88=",
			URI:     "https://vocdoni.io/legal/policy-ilp-v1.pdf",
		},
	}

	// Sign the request
	reqCopy := req
	reqCopy.OrganizerSignature = nil
	canonicalBytes, _ := canon.Encode(reqCopy)
	header := map[string]string{"alg": "RS256", "typ": "JWS"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(canonicalBytes)
	hashed := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, organizerKey, crypto.SHA256, hashed[:])
	
	req.OrganizerSignature = &model.OrganizerSignature{
		Format: "JWS",
		Value:  headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig),
	}

	proposals[id] = &ProposalState{Request: req}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	const tpl = `
<!DOCTYPE html>
<html>
<head>
    <title>VocSign Collector - Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8f9fb; padding: 40px; color: #1a1c1e; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { display: flex; align-items: center; margin-bottom: 40px; }
        .header h1 { margin: 0; color: #3f51b5; }
        .card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #e0e4e8; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
        .title { font-size: 1.25rem; font-weight: bold; margin-bottom: 8px; color: #3f51b5; }
        .promoter { font-size: 0.9rem; color: #666; margin-bottom: 16px; }
        .stats { display: flex; gap: 24px; margin-bottom: 16px; border-top: 1px solid #edf1f5; padding-top: 16px; }
        .stat-item { flex: 1; }
        .stat-label { font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-value { font-size: 1.5rem; font-weight: bold; color: #2e7d32; }
        .link-box { background: #f1f3f9; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 0.9rem; border: 1px dashed #3f51b5; word-break: break-all; }
        .badge { background: #e8f5e9; color: #2e7d32; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VocSign Collector</h1>
        </div>
        
        <h2>Ongoing Legislative Initiatives</h2>
        {{range .Proposals}}
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div class="title">{{.Request.Proposal.Title}}</div>
                    <div class="promoter">Promoted by: <b>{{.Request.Proposal.Promoter}}</b> | ID: {{.Request.RequestID}}</div>
                </div>
                <span class="badge">ACTIVE</span>
            </div>
            <p>{{.Request.Proposal.Summary}}</p>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-label">Verified Signatures</div>
                    <div class="stat-value">{{.Signatures}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Jurisdiction</div>
                    <div style="font-weight: 500;">{{.Request.Proposal.Jurisdiction}}</div>
                </div>
            </div>

            <div class="stat-label" style="margin-bottom: 8px;">VocSign Signing URL</div>
            <div class="link-box">{{$.BaseURL}}/request/{{.Request.RequestID}}</div>
        </div>
        {{end}}
    </div>
</body>
</html>`
	
	pMu.Lock()
	props := make([]*ProposalState, 0, len(proposals))
	for _, p := range proposals { props = append(props, p) }
	pMu.Unlock()

	baseURL := domain
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	data := struct {
		Proposals []*ProposalState
		BaseURL   string
	}{
		Proposals: props,
		BaseURL:   baseURL,
	}

	t := template.Must(template.New("dashboard").Parse(tpl))
	t.Execute(w, data)
}

func handleGetRequest(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/request/")
	p, ok := proposals[id]
	if !ok {
		http.Error(w, "Proposal not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.Request)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/callback/")
	p, ok := proposals[id]
	if !ok {
		http.Error(w, "Proposal not found", http.StatusNotFound)
		return
	}

	var resp model.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(resp.SignatureDerBase64)
	p7, _ := pkcs7.Parse(sigBytes)
	xmlBytes, _ := base64.StdEncoding.DecodeString(resp.SignerXMLBase64)
	
	p7.Content = xmlBytes
	if err := p7.Verify(); err != nil {
		log.Printf("ERROR: Signature verification failed for %s: %v", id, err)
		http.Error(w, "Verification failed", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.Signatures++
	p.Audit = append(p.Audit, resp)
	p.mu.Unlock()

	json.NewEncoder(w).Encode(model.SubmitReceipt{
		Status:     "ok",
		ReceiptID:  uuid.New().String(),
		ReceivedAt: time.Now().Format(time.RFC3339),
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	nBytes := organizerPub.N.Bytes()
	eBytes := make([]byte, 4) 
	eBytes[0] = byte(organizerPub.E >> 24)
	eBytes[1] = byte(organizerPub.E >> 16)
	eBytes[2] = byte(organizerPub.E >> 8)
	eBytes[3] = byte(organizerPub.E)
	for len(eBytes) > 1 && eBytes[0] == 0 { eBytes = eBytes[1:] }

	jwks := map[string]interface{}{
		"keys": []interface{}{map[string]string{
			"kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(nBytes),
			"e": base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
