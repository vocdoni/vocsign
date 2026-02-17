package model

import (
	"encoding/xml"
)

type ILPSignerXML struct {
	XMLName       xml.Name `xml:"SignaturaILP"`
	Versio        string   `xml:"versio,attr"`
	ILP           ILPInfo  `xml:"ILP"`
	Signant       Signant  `xml:"Signant"`
}

type ILPInfo struct {
	Titol string `xml:"Titol"`
	Codi  string `xml:"Codi"`
}

type Signant struct {
	Nom             string `xml:"Nom"`
	Cognom1         string `xml:"Cognom1"`
	Cognom2         string `xml:"Cognom2"`
	DataNaixement   string `xml:"DataNaixement"` // YYYY-MM-DD
	TipusIdentifica string `xml:"TipusIdentificador"` // DNI
	NumIdentifica   string `xml:"NumeroIdentificador"`
}

func GenerateILPXML(req *SignRequest, data Signant) ([]byte, error) {
	obj := ILPSignerXML{
		Versio: "1.0",
		ILP: ILPInfo{
			Titol: req.Proposal.Title,
			Codi:  req.RequestID, // Using RequestID as Code if not specified
		},
		Signant: data,
	}
	
	output, err := xml.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, err
	}
	
	return append([]byte(xml.Header), output...), nil
}
