package sanitizer

import (
	"fmt"
	"regexp"
	vars "wallet_server/pass_vars"
)

var (
	AlphaNumRe = regexp.MustCompile("^[a-zA-Z0-9]*$")
)

func TestDevLibId(devLibId string) error {
	if len(devLibId) != 32 {
		return fmt.Errorf("error: lenght of devLibId = %v", len(devLibId))
	}
	if AlphaNumRe.MatchString(devLibId) {
		return nil
	}
	return fmt.Errorf("error: devLibId not alphanumeric")
}

func TestPassTypeId(passTypeId string) error {
	for _, pass := range vars.PassTypeIds {
		if passTypeId == pass {
			return nil
		}
	}
	return fmt.Errorf("error: passTypeId is undefined")
}

func TestSerialNum(serialNum string) error {
	if AlphaNumRe.MatchString(serialNum) {
		return nil
	}
	return fmt.Errorf("error: serialNum not alphanumeric")
}

func TestRegisterInput(devLibId, passTypeId, serialNum string) (error, error, error) {
	return TestDevLibId(devLibId), TestPassTypeId(passTypeId), TestSerialNum(serialNum)
}

func CheckLoginName(name string) error {
	if len(name) > 32 {
		return fmt.Errorf("error: lenght of name = %v", len(name))
	}
	if AlphaNumRe.MatchString(name) {
		return nil
	}
	return fmt.Errorf("error: name not alphanumeric")
}

func TestPushToken(pushTkn string) error {
	if AlphaNumRe.MatchString(pushTkn) {
		return nil
	}
	return fmt.Errorf("error: push token not alphanumeric")
}
