package main

import (
	"log"
	"net/http"
	"time"
	auth "wallet_server/authentication"
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

	router.GET(getupdatableURL, endpointsENV.GETupdatablepass) // gets updatable passes

	// group that requires authentication
	wallet := router.Group("/")
	wallet.Use(auth.VerifyWalletAuthHeader())
	{
		wallet.POST(registerURL, endpointsENV.POSTregister)     // register device for update notifications
		wallet.DELETE(registerURL, endpointsENV.DELETEregister) // delete device from update notifications
		wallet.GET(updatedpassURL, endpointsENV.GETupdatedpass) // sends updatable passes
	}

	return router
}

func router4Website(endpointsENV *endpoints.Env) http.Handler {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.Static("/static", "./static")
	router.LoadHTMLGlob("static/templates/*")

	router.NoRoute(endpoints.GETnotfound) // 404 error handler
	router.GET(loginURL, endpoints.GETlogin)
	router.POST(loginURL, endpointsENV.POSTlogin)

	// group that requires authentication
	website := router.Group("/")
	website.Use(jwt.VerifyToken())
	{
		website.GET(passesURL, endpoints.GETpasses)
		website.GET(updateURL, endpoints.GETupdate)
		website.GET(updatepassURL, endpoints.GETupdatepass)
		website.POST(updatepassURL, endpoints.POSTupdatepass)
		website.GET(commitURL, endpoints.GETcommit)
		website.POST(commitURL, endpointsENV.POSTcommit)
		website.GET(generatableURL, endpoints.GETgeneratable)
		website.GET(generateWithInfoURL, endpoints.GETgenerateWithInfo)
		website.POST(generateWithInfoURL, endpointsENV.POSTgenerateWithInfo)
		website.GET(generateURL, endpointsENV.GETnewpass_from_webmanager)
		website.GET(statsURL, endpoints.GETstats)
	}

	return router
}

func router4SideAPIs(endpointsENV *endpoints.Env) http.Handler {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// group for scanner. requires authentication
	scanner := router.Group("/scan")
	scanner.Use(auth.VerifyScannerAuthHeader())
	{
		scanner.POST(scanURL, endpointsENV.POSTscan)
	}

	// group for payment system. requires authentication
	paymentSystem := router.Group("/passes")
	paymentSystem.Use(auth.VerifyPaymentSystemAuthHeader())
	{
		paymentSystem.GET(requestpassURL, endpointsENV.GETnewpass_from_api_call)
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

	// servers for different apis
	server4Wallet := &http.Server{
		Addr:         ":8000",
		Handler:      router4Wallet(endpointsENV),
		ReadTimeout:  6 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server4Website := &http.Server{
		Addr:         ":8080",
		Handler:      router4Website(endpointsENV),
		ReadTimeout:  4 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server4SideAPIs := &http.Server{
		Addr:         ":8001",
		Handler:      router4SideAPIs(endpointsENV),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// run servers in error group
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

	g.Go(func() error {
		err := server4SideAPIs.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return err
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
