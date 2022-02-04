package classes

import "database/sql"

type Device struct {
	ID       int
	DevLibId string
	PushTkn  string
	RegDate  string
	Log      sql.NullString
}
