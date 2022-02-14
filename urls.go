package main

// Apple wallet urls
var (
	registerURL     = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber"
	getupdatableURL = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier"
	updatedpassURL  = "/v1/passes/:passTypeIdentifier/:serialNumber"
)

// Website urls
var (
	loginURL       = "/login"
	passesURL      = "/passes"
	updateURL      = "/update"
	updatepassURL  = "/update/:passType"
	commitURL      = "/commit"
	generatableURL = "/generate"
	generateURL    = "/generate/:passType"
	statsURL       = "/stats"
)
