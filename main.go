package main

import (
	"log"
	"net/http"
	"time"
	"wallet_server/authentication"
	"wallet_server/dbconn"
	"wallet_server/endpoints"
	"wallet_server/jwt"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

var (
	g errgroup.Group
)

func router4Wallet(endpointsENV *endpoints.Env) http.Handler {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.GET(updatablepassesURL, endpointsENV.GETupdatepass) // send latest passes

	// group that requires authentication
	wallet := router.Group("/")
	wallet.Use(authentication.VerifyAuthHeader())
	{
		wallet.POST(registerURL, endpointsENV.POSTregister)     // register device for update notifications
		wallet.DELETE(registerURL, endpointsENV.DELETEregister) // delete device from update notifications
		wallet.GET(sendupdatedpassURL, endpointsENV.GETupdatedpass)
	}

	return router
}

func router4Website(endpointsENV *endpoints.Env) http.Handler {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.Static("/static", "./static")
	router.LoadHTMLGlob("static/templates/*")

	router.GET(loginURL, endpoints.GETlogin)
	router.POST(loginURL, endpointsENV.POSTlogin)

	// roup that requires authentication
	website := router.Group("/")
	website.Use(jwt.VerifyToken())
	{
		website.GET(passesURL, endpoints.GETpasses)
		website.GET(updateURL, endpoints.GETupdate)
		website.POST(updateURL, endpoints.POSTupdate)
		website.GET(commitURL, endpoints.GETcommit)
		website.POST(commitURL, endpoints.POSTcommit)
	}

	return router
}

func main() {
	// connect to realational db
	db := new(dbconn.MYSQLConn)
	db.Connect()
	endpointsENV := &endpoints.Env{ // environment for endpoints
		DB: db,
	}

	server4Wallet := &http.Server{
		Addr:         ":8080",
		Handler:      router4Wallet(endpointsENV),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server4Website := &http.Server{
		Addr:         ":8000",
		Handler:      router4Website(endpointsENV),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	g.Go(func() error {
		err := server4Wallet.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return err
	})

	g.Go(func() error {
		err := server4Website.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return err
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
