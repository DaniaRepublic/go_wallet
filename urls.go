package main

// Apple wallet urls
var (
	registerURL      = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber"
	getupdatableURL  = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier"
	sendupdatableURL = "/v1/passes/:passTypeIdentifier/:serialNumber"
)

// Website urls
var (
	loginURL  = "/login"
	passesURL = "/passes"
	updateURL = "/update"
	commitURL = "/commit"
	statsURL  = "/stats"
)
