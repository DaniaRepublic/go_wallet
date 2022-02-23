package main

// Apple wallet uris
var (
	registerURL     = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber"
	getupdatableURL = "/v1/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier"
	updatedpassURL  = "/v1/passes/:passTypeIdentifier/:serialNumber"
)

// Website uris
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

// Scanner uris
var (
	scanURL = "/:passType/:serialNumber"
)

// Payment system uris
var (
	requestpassURL = "/:passType"
)
