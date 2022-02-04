package dbconn

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/go-sql-driver/mysql"
)

type MYSQLConn struct {
	DB *sql.DB
}

func (conn *MYSQLConn) Connect() {
	cfg := mysql.Config{
		User:   os.Getenv("MYSQL_USER"),
		Passwd: os.Getenv("MYSQL_PASS"),
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "wallet",
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(fmt.Errorf("error opening MYSQL: %v", err))
	}

	if pingErr := db.Ping(); pingErr != nil {
		log.Fatal(fmt.Errorf("error in MYSQL ping: %v", pingErr))
	}

	conn.DB = db
}
