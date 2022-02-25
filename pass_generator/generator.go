package pass_generator

import (
	"encoding/json"
	"os"
	"wallet_server/passkit"
)

var (
	WALLET_SERV_ADDR = os.Getenv("WALLET_SERV_ADDR")
)

func GenerateEventTicket(serialNum, eventName, startTime, endTime, passType string) ([]byte, error) {
	passJson := passkit.NewEventTicket()
	// ticket fields
	primaryField := passkit.Field{
		Key:           "event",
		Label:         "EVENT:",
		Value:         eventName,
		ChangeMessage: "%@",
	}
	secondaryField1 := passkit.Field{
		Key:   "start",
		Label: "START:",
		Value: startTime,
	}
	secondaryField2 := passkit.Field{
		Key:   "end",
		Label: "END:",
		Value: endTime,
	}
	auxiliaryField := passkit.Field{
		Key:   "clitype",
		Label: "STATUS:",
		Value: passType,
	}

	passJson.AddPrimaryFields(primaryField)
	passJson.AddSecondaryFields(secondaryField1)
	passJson.AddSecondaryFields(secondaryField2)
	passJson.AddAuxiliaryFields(auxiliaryField)

	// pass.json contents
	passTypeId := "pass.art4." + passType + ".Card"
	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "G63G4WSKWU",
		PassTypeIdentifier:  passTypeId,
		AuthenticationToken: os.Getenv("AUTH_TOKEN"),
		WebServiceURL:       WALLET_SERV_ADDR,
		OrganizationName:    "Art4",
		SerialNumber:        serialNum,
		Description:         "Art4 Event Ticket",
		EventTicket:         passJson,
		Barcodes: []passkit.Barcode{
			{
				Format:          passkit.BarcodeFormatQR,
				Message:         serialNum + "@" + passType,
				MessageEncoding: "iso-8859-1",
			},
		},
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return nil, err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return nil, err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return nil, err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return nil, err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return nil, err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return nil, err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(&pass, memTemplate, signInfo)
	if err != nil {
		return nil, err
	}

	// return pass bytes
	return passZipBytes, nil
}

func GenerateEventTicketForCommit(eventName, startTime, endTime, passType string) error {
	pass, err := GenerateJsonPassTemplate(eventName, startTime, endTime, passType)
	if err != nil {
		return nil
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(pass, memTemplate, signInfo)
	if err != nil {
		return err
	}
	// save pass
	err = os.WriteFile(projectDir+"/static/passes/new_passes/"+passType+".pkpass", passZipBytes, 0644)
	if err != nil {
		return err
	}

	// return pass bytes
	return nil
}

func GenerateYearlyCard(serialNum, eventName, startTime, endTime, userName, passType string) ([]byte, error) {
	passJson := passkit.NewEventTicket()
	// ticket fields
	primaryField := passkit.Field{
		Key:           "event",
		Label:         "EVENT:",
		Value:         eventName,
		ChangeMessage: "%@",
	}
	secondaryField1 := passkit.Field{
		Key:   "start",
		Label: "START:",
		Value: startTime,
	}
	secondaryField2 := passkit.Field{
		Key:   "end",
		Label: "END:",
		Value: endTime,
	}
	auxiliaryField1 := passkit.Field{
		Key:   "clitype",
		Label: "STATUS:",
		Value: passType,
	}
	auxiliaryField2 := passkit.Field{
		Key:   "username",
		Label: "USERNAME:",
		Value: userName,
	}

	passJson.AddPrimaryFields(primaryField)
	passJson.AddSecondaryFields(secondaryField1)
	passJson.AddSecondaryFields(secondaryField2)
	passJson.AddAuxiliaryFields(auxiliaryField1)
	passJson.AddAuxiliaryFields(auxiliaryField2)

	// pass.json contents
	passTypeId := "pass.art4." + passType + ".Card"
	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "G63G4WSKWU",
		PassTypeIdentifier:  passTypeId,
		AuthenticationToken: os.Getenv("AUTH_TOKEN"),
		WebServiceURL:       WALLET_SERV_ADDR,
		OrganizationName:    "Art4",
		SerialNumber:        serialNum,
		Description:         "Art4 Event Ticket",
		EventTicket:         passJson,
		Barcodes: []passkit.Barcode{
			{
				Format:          passkit.BarcodeFormatQR,
				Message:         serialNum + "@" + passType,
				MessageEncoding: "iso-8859-1",
			},
		},
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return nil, err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return nil, err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return nil, err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return nil, err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return nil, err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return nil, err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(&pass, memTemplate, signInfo)
	if err != nil {
		return nil, err
	}

	// return pass bytes
	return passZipBytes, nil
}

func GenerateYearlyCardForCommit(eventName, startTime, endTime, passType string) error {
	pass, err := GenerateJsonPassTemplate(eventName, startTime, endTime, passType)
	if err != nil {
		return nil
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(pass, memTemplate, signInfo)
	if err != nil {
		return err
	}
	// save pass
	err = os.WriteFile(projectDir+"/static/passes/new_passes/"+passType+".pkpass", passZipBytes, 0644)
	if err != nil {
		return err
	}

	// return pass bytes
	return nil
}

func GenerateCollectorsCard(serialNum, eventName, startTime, endTime, userName, passType string) ([]byte, error) {
	passJson := passkit.NewEventTicket()
	// ticket fields
	primaryField := passkit.Field{
		Key:           "event",
		Label:         "EVENT:",
		Value:         eventName,
		ChangeMessage: "%@",
	}
	secondaryField1 := passkit.Field{
		Key:   "start",
		Label: "START:",
		Value: startTime,
	}
	secondaryField2 := passkit.Field{
		Key:   "end",
		Label: "END:",
		Value: endTime,
	}
	auxiliaryField1 := passkit.Field{
		Key:   "clitype",
		Label: "STATUS:",
		Value: passType,
	}
	auxiliaryField2 := passkit.Field{
		Key:   "username",
		Label: "USERNAME:",
		Value: userName,
	}

	passJson.AddPrimaryFields(primaryField)
	passJson.AddSecondaryFields(secondaryField1)
	passJson.AddSecondaryFields(secondaryField2)
	passJson.AddAuxiliaryFields(auxiliaryField1)
	passJson.AddAuxiliaryFields(auxiliaryField2)

	// pass.json contents
	passTypeId := "pass.art4." + passType + ".Card"
	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "G63G4WSKWU",
		PassTypeIdentifier:  passTypeId,
		AuthenticationToken: os.Getenv("AUTH_TOKEN"),
		WebServiceURL:       WALLET_SERV_ADDR,
		OrganizationName:    "Art4",
		SerialNumber:        serialNum,
		Description:         "Art4 Event Ticket",
		EventTicket:         passJson,
		Barcodes: []passkit.Barcode{
			{
				Format:          passkit.BarcodeFormatQR,
				Message:         serialNum + "@" + passType,
				MessageEncoding: "iso-8859-1",
			},
		},
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return nil, err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return nil, err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return nil, err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return nil, err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return nil, err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return nil, err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(&pass, memTemplate, signInfo)
	if err != nil {
		return nil, err
	}

	// return pass bytes
	return passZipBytes, nil
}

func GenerateCollectorsCardForCommit(eventName, startTime, endTime, passType string) error {
	pass, err := GenerateJsonPassTemplate(eventName, startTime, endTime, passType)
	if err != nil {
		return nil
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return err
	}

	// load pass media content
	bytesLogo, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo.png")
	if err != nil {
		return err
	}
	bytesLogo2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/logo@2x.png")
	if err != nil {
		return err
	}
	bytesIcon, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon.png")
	if err != nil {
		return err
	}
	bytesIcon2x, err := os.ReadFile(projectDir + "/static/passes/current_media/" + passType + "/icon@2x.png")
	if err != nil {
		return err
	}

	genDir := projectDir + "/dyn_pass_gen"

	memTemplate := passkit.NewInMemoryPassTemplate()
	memTemplate.AddFileBytes(passkit.BundleLogo, bytesLogo)
	memTemplate.AddFileBytes(passkit.BundleLogoRetina, bytesLogo2x)
	memTemplate.AddFileBytes(passkit.BundleIcon, bytesIcon)
	memTemplate.AddFileBytes(passkit.BundleIconRetina, bytesIcon2x)
	err = memTemplate.AddAllFiles(genDir + "/passes/" + passType)
	if err != nil {
		return err
	}
	// sign pass
	signInfo, err := passkit.LoadSigningInformationFromFiles(genDir+"/certs/"+passType+".p12", "Dania2100", genDir+"/certs/AppleWWDRCA.cer")
	if err != nil {
		return err
	}
	signer := passkit.NewMemoryBasedSigner()
	passZipBytes, err := signer.CreateSignedAndZippedPassArchive(pass, memTemplate, signInfo)
	if err != nil {
		return err
	}
	// save pass
	err = os.WriteFile(projectDir+"/static/passes/new_passes/"+passType+".pkpass", passZipBytes, 0644)
	if err != nil {
		return err
	}

	// return pass bytes
	return nil
}

func GenerateJsonPassTemplate(eventName, startTime, endTime, passType string) (*passkit.Pass, error) {
	passJson := passkit.NewEventTicket()
	// ticket fields
	primaryField := passkit.Field{
		Key:           "event",
		Label:         "EVENT:",
		Value:         eventName,
		ChangeMessage: "%@",
	}
	secondaryField1 := passkit.Field{
		Key:   "start",
		Label: "START:",
		Value: startTime,
	}
	secondaryField2 := passkit.Field{
		Key:   "end",
		Label: "END:",
		Value: endTime,
	}
	auxiliaryField1 := passkit.Field{
		Key:   "clitype",
		Label: "STATUS:",
		Value: passType,
	}
	auxiliaryField2 := passkit.Field{
		Key:   "username",
		Label: "USERNAME:",
		Value: "John Doe Jr.",
	}

	passJson.AddPrimaryFields(primaryField)
	passJson.AddSecondaryFields(secondaryField1)
	passJson.AddSecondaryFields(secondaryField2)
	passJson.AddAuxiliaryFields(auxiliaryField1)
	passJson.AddAuxiliaryFields(auxiliaryField2)

	// pass.json contents
	passTypeId := "pass.art4." + passType + ".Card"
	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "G63G4WSKWU",
		PassTypeIdentifier:  passTypeId,
		AuthenticationToken: "The authenticationToken needs to be at least 16 characters long",
		WebServiceURL:       "https://url",
		OrganizationName:    "Art4",
		SerialNumber:        "QQQQWWWWEEEERRRR",
		Description:         "Art4 Event Ticket",
		EventTicket:         passJson,
		Barcodes: []passkit.Barcode{
			{
				Format:          passkit.BarcodeFormatQR,
				Message:         "QQQQWWWWEEEERRRR" + "@" + passType,
				MessageEncoding: "iso-8859-1",
			},
		},
	}

	passBytes, err := json.Marshal(pass)
	if err != nil {
		return nil, err
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(projectDir+"/dyn_pass_gen/passes/"+passType+"/"+passType+".json", passBytes, 0644)
	if err != nil {
		return nil, err
	}

	return &pass, nil
}
