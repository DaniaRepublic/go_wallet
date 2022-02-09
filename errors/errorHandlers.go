package errors

import "log"

var DefaultErrHandler = func(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
