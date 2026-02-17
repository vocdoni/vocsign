//go:build cgo

package pkcs12store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"unsafe"

	"github.com/miekg/pkcs11"
)

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func getDigestPrefix(hash crypto.Hash) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch hash {
	case crypto.SHA256:
		oid = oidSHA256
	case crypto.SHA1:
		oid = oidSHA1
	case crypto.SHA384:
		oid = oidSHA384
	case crypto.SHA512:
		oid = oidSHA512
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hash)
	}

	di := digestInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
	}
	// Marshal the prefix by creating a full DigestInfo and taking everything before the hash bytes.
	// Standard hash sizes: SHA1=20, SHA256=32, SHA384=48, SHA512=64
	di.Digest = make([]byte, hash.Size())
	full, err := asn1.Marshal(di)
	if err != nil {
		return nil, err
	}
	return full[:len(full)-hash.Size()], nil
}

type PKCS11Signer struct {
	LibPath    string
	ProfileDir string
	Slot       uint
	ID         []byte
	PublicKey  crypto.PublicKey
}

func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	log.Printf("DEBUG: PKCS11Signer.Sign called for Slot %d, Profile %s", s.Slot, s.ProfileDir)
	p := pkcs11.New(s.LibPath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 lib")
	}

	os.Setenv("NSS_CONFIG_DIR", "sql:"+s.ProfileDir)
	_ = p.Finalize()

	params := fmt.Sprintf("configdir='sql:%s' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly", s.ProfileDir)
	pByte := append([]byte(params), 0)
	pPtr := unsafe.Pointer(&pByte[0])

	if err := p.Initialize(pkcs11.InitializeWithReserved(pPtr)); err != nil {
		_ = p.Initialize()
	}
	defer p.Finalize()

	session, err := p.OpenSession(s.Slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, err
	}
	defer p.CloseSession(session)

	_ = p.Login(session, pkcs11.CKU_USER, "")

	p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, s.ID),
	})
	objs, _, err := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)
	if err != nil || len(objs) == 0 {
		return nil, fmt.Errorf("private key not found in slot %d", s.Slot)
	}

	// Sign
	var mechanism *pkcs11.Mechanism
	switch s.PublicKey.(type) {
	case *rsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

		hashAlg := opts.HashFunc()
		log.Printf("DEBUG: RSA Sign with hash %v (digest len: %d)", hashAlg, len(digest))

		prefix, err := getDigestPrefix(hashAlg)
		if err != nil {
			return nil, err
		}

		// Combine prefix and digest
		digest = append(prefix, digest...)

	case *ecdsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	if err := p.SignInit(session, []*pkcs11.Mechanism{mechanism}, objs[0]); err != nil {
		log.Printf("DEBUG: SignInit failed: %v", err)
		return nil, err
	}

	sig, err := p.Sign(session, digest)
	if err != nil {
		log.Printf("DEBUG: Sign failed: %v", err)
		return nil, err
	}

	if _, ok := s.PublicKey.(*ecdsa.PublicKey); ok {
		if len(sig)%2 != 0 {
			return nil, fmt.Errorf("invalid ECDSA signature length")
		}
		n := len(sig) / 2
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])

		return asn1.Marshal(struct{ R, S *big.Int }{r, s})
	}
	log.Printf("DEBUG: Signature successful, size: %d", len(sig))
	return sig, nil
}
