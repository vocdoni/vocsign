package pkcs12store

import (
	"errors"
	"fmt"
)

// This file intentionally contains a minimal BER-to-DER normalizer.
//
// Why this exists:
// software.sslmate.com/src/go-pkcs12 decodes DER-only PKCS#12, but some real-world
// certificates (notably legacy idCAT exports) are BER encoded with indefinite lengths.
// We normalize BER to DER before delegating the actual PKCS#12 decoding to go-pkcs12.

// normalizeBER converts BER (including indefinite lengths and constructed
// OCTET STRINGs) into DER so strict ASN.1 decoders can parse legacy PKCS#12.
func normalizeBER(input []byte) ([]byte, error) {
	p := &berParser{b: input}
	der, err := p.parseElement()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.b) {
		return nil, errors.New("trailing data after BER conversion")
	}
	return der, nil
}

type berParser struct {
	b   []byte
	pos int
}

const (
	asn1ClassMask       = 0xC0
	asn1ClassContext    = 0x80
	asn1ConstructedMask = 0x20
	asn1TagMask         = 0x1F
	asn1TagOctetString  = 0x04
)

func (p *berParser) parseElement() ([]byte, error) {
	tag, tagBytes, err := p.readTag()
	if err != nil {
		return nil, err
	}

	length, indefinite, err := p.readLength()
	if err != nil {
		return nil, err
	}

	constructed := (tag & asn1ConstructedMask) != 0
	class := tag & asn1ClassMask
	tagNumber := tag & asn1TagMask

	var content []byte
	if indefinite {
		if !constructed {
			return nil, errors.New("invalid BER: primitive with indefinite length")
		}
		var chunks [][]byte
		for {
			if p.remaining() < 2 {
				return nil, errors.New("invalid BER: missing EOC for indefinite length")
			}
			if p.b[p.pos] == 0x00 && p.b[p.pos+1] == 0x00 {
				p.pos += 2
				break
			}
			child, err := p.parseElement()
			if err != nil {
				return nil, err
			}
			chunks = append(chunks, child)
		}

		// BER allows constructed OCTET STRING, DER requires primitive form.
		if class == 0 && tagNumber == asn1TagOctetString {
			flattened, err := flattenConstructedOctetString(chunks)
			if err != nil {
				return nil, err
			}
			content = maybeNormalizeASN1Bytes(flattened)
			tagBytes = []byte{asn1TagOctetString}
		} else if class == asn1ClassContext && tagNumber == 0 && len(chunks) > 1 {
			if flattened, ok := flattenPrimitiveOctetChildren(chunks); ok {
				content = flattened
				tagBytes = clearConstructedBit(tagBytes)
			} else {
				content = joinChunks(chunks)
			}
		} else {
			content = joinChunks(chunks)
		}
	} else {
		if p.remaining() < length {
			return nil, errors.New("invalid BER: content truncated")
		}
		rawContent := p.b[p.pos : p.pos+length]
		p.pos += length

		if constructed {
			childParser := &berParser{b: rawContent}
			var chunks [][]byte
			for childParser.pos < len(childParser.b) {
				child, err := childParser.parseElement()
				if err != nil {
					return nil, err
				}
				chunks = append(chunks, child)
			}

			if class == 0 && tagNumber == asn1TagOctetString {
				flattened, err := flattenConstructedOctetString(chunks)
				if err != nil {
					return nil, err
				}
				content = maybeNormalizeASN1Bytes(flattened)
				tagBytes = []byte{asn1TagOctetString}
			} else if class == asn1ClassContext && tagNumber == 0 && len(chunks) > 1 {
				if flattened, ok := flattenPrimitiveOctetChildren(chunks); ok {
					content = flattened
					tagBytes = clearConstructedBit(tagBytes)
				} else {
					content = joinChunks(chunks)
				}
			} else {
				content = joinChunks(chunks)
			}
		} else {
			content = rawContent
		}
	}

	return encodeDER(tagBytes, content), nil
}

func (p *berParser) readTag() (byte, []byte, error) {
	if p.remaining() < 1 {
		return 0, nil, errors.New("invalid BER: missing tag")
	}
	first := p.b[p.pos]
	p.pos++

	// Long-form tag number.
	if first&asn1TagMask == asn1TagMask {
		tagBytes := []byte{first}
		for {
			if p.remaining() < 1 {
				return 0, nil, errors.New("invalid BER: truncated long-form tag")
			}
			b := p.b[p.pos]
			p.pos++
			tagBytes = append(tagBytes, b)
			if b&0x80 == 0 {
				break
			}
		}
		return first, tagBytes, nil
	}

	return first, []byte{first}, nil
}

func (p *berParser) readLength() (int, bool, error) {
	if p.remaining() < 1 {
		return 0, false, errors.New("invalid BER: missing length")
	}
	first := p.b[p.pos]
	p.pos++

	if first == 0x80 {
		return 0, true, nil
	}
	if first < 0x80 {
		return int(first), false, nil
	}

	n := int(first & 0x7F)
	if n == 0 {
		return 0, false, errors.New("invalid BER: reserved length form")
	}
	if p.remaining() < n {
		return 0, false, errors.New("invalid BER: truncated long-form length")
	}

	length := 0
	for i := 0; i < n; i++ {
		length = (length << 8) | int(p.b[p.pos])
		p.pos++
	}
	return length, false, nil
}

func (p *berParser) remaining() int {
	return len(p.b) - p.pos
}

func encodeDER(tag []byte, content []byte) []byte {
	out := make([]byte, 0, len(tag)+8+len(content))
	out = append(out, tag...)
	out = append(out, encodeLength(len(content))...)
	out = append(out, content...)
	return out
}

func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var tmp [8]byte
	i := len(tmp)
	for v := length; v > 0; v >>= 8 {
		i--
		tmp[i] = byte(v)
	}
	n := len(tmp) - i
	out := make([]byte, 1+n)
	out[0] = byte(0x80 | n)
	copy(out[1:], tmp[i:])
	return out
}

func joinChunks(chunks [][]byte) []byte {
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func flattenConstructedOctetString(chunks [][]byte) ([]byte, error) {
	out := make([]byte, 0)
	for _, c := range chunks {
		tag, content, err := decodeSingleDER(c)
		if err != nil {
			return nil, err
		}
		if tag != asn1TagOctetString {
			return nil, fmt.Errorf("invalid constructed OCTET STRING child tag: %d", tag)
		}
		out = append(out, content...)
	}
	return out, nil
}

func flattenPrimitiveOctetChildren(chunks [][]byte) ([]byte, bool) {
	out := make([]byte, 0)
	for _, c := range chunks {
		tag, content, err := decodeSingleDER(c)
		if err != nil || tag != asn1TagOctetString {
			return nil, false
		}
		out = append(out, content...)
	}
	return out, true
}

func clearConstructedBit(tagBytes []byte) []byte {
	if len(tagBytes) == 0 {
		return tagBytes
	}
	out := append([]byte(nil), tagBytes...)
	out[0] = out[0] &^ asn1ConstructedMask
	return out
}

func decodeSingleDER(der []byte) (byte, []byte, error) {
	if len(der) < 2 {
		return 0, nil, errors.New("invalid DER: short element")
	}
	tag := der[0]
	pos := 1
	if der[pos]&asn1TagMask == asn1TagMask {
		for {
			if pos >= len(der) {
				return 0, nil, errors.New("invalid DER: truncated long tag")
			}
			b := der[pos]
			pos++
			if b&0x80 == 0 {
				break
			}
		}
	}
	if pos >= len(der) {
		return 0, nil, errors.New("invalid DER: missing length")
	}

	firstLen := der[pos]
	pos++
	length := 0
	if firstLen < 0x80 {
		length = int(firstLen)
	} else {
		n := int(firstLen & 0x7F)
		if n == 0 || pos+n > len(der) {
			return 0, nil, errors.New("invalid DER: length overflow")
		}
		for i := 0; i < n; i++ {
			length = (length << 8) | int(der[pos])
			pos++
		}
	}
	if pos+length != len(der) {
		return 0, nil, errors.New("invalid DER: trailing data")
	}
	return tag, der[pos : pos+length], nil
}

func maybeNormalizeASN1Bytes(content []byte) []byte {
	if len(content) == 0 || content[0] != 0x30 {
		return content
	}
	normalized, err := normalizeBER(content)
	if err != nil {
		return content
	}
	return normalized
}
