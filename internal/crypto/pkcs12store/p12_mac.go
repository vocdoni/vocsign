package pkcs12store

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"unicode/utf16"
)

// This file recomputes PKCS#12 MACs after BER->DER normalization.
//
// Normalizing BER changes byte-level AuthSafe encoding, invalidating the original MAC.
// To keep decode delegated to go-pkcs12 while still accepting legacy BER files, we
// recompute MAC using the same RFC 7292 (PKCS#12) KDF + HMAC-SHA1.

var oidMacSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

type pfxForMAC struct {
	Version  int
	AuthSafe contentInfoForMAC
	MacData  macDataForMAC `asn1:"optional"`
}

type contentInfoForMAC struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macDataForMAC struct {
	Mac        digestInfoForMAC
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfoForMAC struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

func recomputePFXMAC(der []byte, password string) ([]byte, error) {
	var pfx pfxForMAC
	if _, err := asn1.Unmarshal(der, &pfx); err != nil {
		return nil, err
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, errors.New("pkcs12 has no mac")
	}
	if !pfx.MacData.Mac.Algorithm.Algorithm.Equal(oidMacSHA1) {
		return nil, errors.New("unsupported mac algorithm")
	}

	var authSafeBytes []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeBytes); err != nil {
		return nil, err
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	iters := pfx.MacData.Iterations
	if iters < 1 {
		iters = 1
	}
	pfx.MacData.Mac.Digest = computePKCS12MACSHA1(authSafeBytes, pfx.MacData.MacSalt, encodedPassword, iters)
	return asn1.Marshal(pfx)
}

func computePKCS12MACSHA1(message, salt, password []byte, iterations int) []byte {
	key := pkcs12KDFSHA1(salt, password, iterations, 3, sha1.Size)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func pkcs12KDFSHA1(salt, password []byte, iterations int, id byte, size int) []byte {
	u := sha1.Size
	v := 64

	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}

	var S, P []byte
	if len(salt) > 0 {
		S = make([]byte, v*((len(salt)+v-1)/v))
		for i := range S {
			S[i] = salt[i%len(salt)]
		}
	}
	if len(password) > 0 {
		P = make([]byte, v*((len(password)+v-1)/v))
		for i := range P {
			P[i] = password[i%len(password)]
		}
	}

	I := append(S, P...)
	result := make([]byte, size)
	for i := 0; i < (size+u-1)/u; i++ {
		h := sha1.New()
		_, _ = h.Write(D)
		_, _ = h.Write(I)
		Ai := h.Sum(nil)
		for j := 1; j < iterations; j++ {
			h = sha1.New()
			_, _ = h.Write(Ai)
			Ai = h.Sum(nil)
		}
		copy(result[i*u:], Ai)

		if i*u+u < size {
			B := make([]byte, v)
			for j := range B {
				B[j] = Ai[j%u]
			}
			for j := 0; j < len(I)/v; j++ {
				block := I[j*v : (j+1)*v]
				carry := uint16(1)
				for k := v - 1; k >= 0; k-- {
					sum := uint16(block[k]) + uint16(B[k]) + carry
					block[k] = byte(sum)
					carry = sum >> 8
				}
			}
		}
	}
	return result
}

func bmpStringZeroTerminated(s string) ([]byte, error) {
	for _, r := range s {
		if r > 0xFFFF {
			return nil, errors.New("password contains unsupported unicode character")
		}
	}
	utf16Data := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(utf16Data)*2+2)
	for _, r := range utf16Data {
		out = append(out, byte(r>>8), byte(r))
	}
	// PKCS#12 BMPString passwords are NUL-terminated.
	out = append(out, 0x00, 0x00)
	return out, nil
}
