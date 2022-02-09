package pass_generator

import (
	"os"
	"wallet_server/passkit"
)

func GenerateEventTicket(serialNum, eventName, startTime, endTime string) ([]byte, error) {
	passJson := passkit.NewEventTicket()
	// ticket fields
	primaryField := passkit.Field{
		Key:           "event",
		Label:         "EVENT:",
		Value:         eventName,
		ChangeMessage: "%@",
	}
	secondaryField1 := passkit.Field{
		Key:   "loc",
		Label: "STARTS:",
		Value: startTime,
	}
	secondaryField2 := passkit.Field{
		Key:   "loc",
		Label: "ENDS:",
		Value: endTime,
	}
	auxiliaryField := passkit.Field{
		Key:   "clitype",
		Label: "YOUR STATUS:",
		Value: "COMMON.",
	}

	passJson.AddPrimaryFields(primaryField)
	passJson.AddSecondaryFields(secondaryField1)
	passJson.AddSecondaryFields(secondaryField2)
	passJson.AddAuxiliaryFields(auxiliaryField)

	// pass.json contents
	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "G63G4WSKWU",
		PassTypeIdentifier:  "pass.art4.common.Card",
		AuthenticationToken: os.Getenv("AUTH_TOKEN"),
		WebServiceURL:       "https://3181-195-91-208-19.ngrok.io/",
		OrganizationName:    "Art4",
		SerialNumber:        serialNum,
		Description:         "Art4 Event Ticket",
		EventTicket:         passJson,
		Barcodes: []passkit.Barcode{
			{
				Format:          passkit.BarcodeFormatQR,
				Message:         "https://www.art4.ru/show/v-pyli-etoy-planety/",
				MessageEncoding: "iso-8859-1",
			},
		},
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	genDir := projectDir + "/dyn_pass_gen"

	// load pass media content
	bytesLogo, err := os.ReadFile(genDir + "/passes/common_current/logo.png")
	if err != nil {
		return nil, err
	}
	bytesLogo2x, err := os.ReadFile(genDir + "/passes/common_current/logo@2x.png")
	if err != nil {
		return nil, err
	}
	bytesIcon, err := os.ReadFile(genDir + "/passes/common_current/icon.png")
	if err != nil {
		return nil, err
	}
	bytesIcon2x, err := os.ReadFile(genDir + "/passes/common_current/icon@2x.png")
	if err != nil {
		return nil, err
	}

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/common_new")
	if err != nil {
		return nil, err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/common.p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return nil, err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(&pass, memTemplate, signInfo)
	if err != nil {
		return nil, err
	}
	// save pass
	err = os.WriteFile(genDir+"/passes/common.pkpass", passZipBytes, 0644)
	if err != nil {
		return nil, err
	}

	// if saved successfully

	return passZipBytes, nil
}
