package endpoints

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
	"wallet_server/classes"
	"wallet_server/dbconn"
	"wallet_server/jwt"
	"wallet_server/sanitizer"

	"github.com/gin-gonic/gin"
)

type Env struct {
	DB *dbconn.MYSQLConn // pointer to mysql connection
}

const JWT_TTL int = 2700 // 2700 seconds = 45 min

// pass names for POSTupdate handler
var AllPassnames []string = []string{
	"collectors.pkpass",
	"common.pkpass",
	"yearly.pkpass",
}

var DefaultErrHandler = func(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

/*
\
Next come endpoints handlers for WALLET server ->
  /
*/

func (e *Env) POSTregister(c *gin.Context) { // new device<->token registration
	/*
		pass serial number needs to be unique for every pass. (e.g. UUID)
	*/
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2, err3 := sanitizer.TestRegisterInput(devLibId, passTypeId, serialNum)
	if err1 != nil || err2 != nil || err3 != nil {
		log.Fatalf("error in register input: devLibIdError=%v, passTypeIdError=%v, serialNumError=%v", err1, err2, err3)
	}

	var exists int
	// check if device is already registered
	row := e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from wallet.Device WHERE deviceLibraryIdentifier = ?);`, devLibId)
	if row.Scan(&exists); exists == 1 {
		log.Fatal("error: user already registered")
	}
	// check if pass exists
	row = e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from wallet.Pass WHERE serialNumber = ?)`, serialNum)
	if row.Scan(&exists); exists == 1 {
		log.Fatal("error: pass already registered")
	} else {
		// register pass
		_, err := e.DB.DB.Exec("INSERT INTO wallet.Pass (passTypeIdentifier, serialNumber) VALUES (?, ?)", passTypeId, serialNum)
		if err != nil {
			log.Fatalf("error inserting Device information: %v", err.Error())
		}
	}

	body, err := ioutil.ReadAll(c.Request.Body) // push token is in the body
	if err != nil {
		log.Fatalf("error no body pushToken: %v", err.Error())
	}
	var pushTkn classes.PushTkn
	err = json.Unmarshal(body, &pushTkn)
	if err != nil {
		log.Fatalf("error decoding json body")
	}

	// register device
	_, err = e.DB.DB.Exec("INSERT INTO Device (deviceLibraryIdentifier, pushToken) VALUES (?, ?)", devLibId, pushTkn.PushToken)
	if err != nil {
		log.Fatalf("error inserting Device information: %v", err.Error())
	}

	// create regestration
	_, err = e.DB.DB.Exec("INSERT INTO wallet.Registration (Device_devLibId, Pass_passTypeId, Pass_serialNum) VALUES (?, ?, ?)", devLibId, passTypeId, serialNum)
	if err != nil {
		log.Fatalf("error inserting Registration: %v", err.Error())
	}
}

func (e *Env) DELETEregister(c *gin.Context) {
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2, err3 := sanitizer.TestRegisterInput(devLibId, passTypeId, serialNum)
	if err1 != nil || err2 != nil || err3 != nil {
		log.Fatalf("error in unregister input: devLibId=%v, passTypeId=%v, serialNum=%v", err1, err2, err3)
	}

	var exists int
	// get device and pass ids
	row := e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from wallet.Registration WHERE (Device_devLibId, Pass_passTypeId, Pass_serialNum) = (?, ?, ?))`, devLibId, passTypeId, serialNum)
	if row.Scan(&exists); exists == 0 {
		log.Fatal("error trying to unregister device: it isn't registered")
	}
	// delete regestration
	_, err := e.DB.DB.Exec("DELETE FROM Registration WHERE (Device_devLibId, Pass_passTypeId, Pass_serialNum) = (?, ?, ?)", devLibId, passTypeId, serialNum)
	if err != nil {
		log.Fatalf("error deleting registration: %v", err.Error())
	}

	row = e.DB.DB.QueryRow("SELECT EXISTS(SELECT * from wallet.Registration WHERE Device_devLibId = ?)", devLibId)

	if row.Scan(&exists); exists == 0 {
		// if device is not regestered for any other passes then delete it
		_, err := e.DB.DB.Exec("DELETE FROM wallet.Device WHERE deviceLibraryIdentifier = ?", devLibId)
		if err != nil {
			log.Fatalf("error deleting device: %v", err.Error())
		}
	}
}

func (e *Env) GETupdatablepass(c *gin.Context) {
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	err1, err2 := sanitizer.TestDevLibId(devLibId), sanitizer.TestPassTypeId(passTypeId)
	if err1 != nil || err2 != nil {
		log.Fatalf("error in GETupdatablepass uri: devLibId=%v, passTypeId=%v", err1, err2)
	}
	fmt.Println(devLibId, passTypeId)

	lastUpdatedUnix, err := strconv.Atoi(c.Request.URL.Query().Get("passesUpdatedSince")) // should contain lastupdated tag value
	if err != nil && lastUpdatedUnix != 0 {
		log.Fatalf("error wrong update tag %v", err)
	}
	row := e.DB.DB.QueryRow("SELECT lastUpdateTag FROM UpdateTag WHERE passTypeId = ?", passTypeId) // retrieve actual last update tag
	var actualLastUpdatedUnix int
	if row.Scan(&actualLastUpdatedUnix) != nil {
		log.Fatal("error geting last updated tag")
	}

	fmt.Println(lastUpdatedUnix, actualLastUpdatedUnix)
	var (
		updatableSerialNums []string
		serialNum           string
		//exists              int
	)
	// update only if last updated tag is newer
	if actualLastUpdatedUnix > lastUpdatedUnix {
		// get serial numbers of passes with larger lastupdated tags
		//row = e.DB.DB.QueryRow("SELECT EXISTS(SELECT * from wallet.Registration WHERE (Device_devLibId, Pass_passTypeId) = (?, ?))", devLibId, passTypeId)
		//if row.Scan(&exists); exists == 0 {
		//	log.Fatalf("error Registration for Device_devLibId=%v, Pass_passTypeId%v is not found", devLibId, passTypeId)
		//}
		rows, err := e.DB.DB.Query("SELECT Pass_serialNum FROM Registration WHERE (Device_devLibId, Pass_passTypeId) = (?, ?)", devLibId, passTypeId)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()
		//if row.Scan(&serialNum) != nil {
		//	log.Fatal("error geting last updated tag")
		//}
		//fmt.Println(serialNum)
		for rows.Next() {
			if err = row.Scan(&serialNum); err != nil {
				fmt.Println(serialNum)
				log.Fatalf("error getting serial number from Registration table: Device_devLibId= %v, Pass_passTypeId= %v ; %v", devLibId, passTypeId, err.Error())
			}
			updatableSerialNums = append(updatableSerialNums, serialNum)
		}
	}

	fmt.Println(updatableSerialNums)

	c.JSON(http.StatusOK, gin.H{
		"serialNumbers": updatableSerialNums,
		"lastUpdated":   strconv.Itoa(actualLastUpdatedUnix),
	})
}

func (e *Env) GETupdatedpass(c *gin.Context) {
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2 := sanitizer.TestPassTypeId(passTypeId), sanitizer.TestSerialNum(serialNum)
	if err1 != nil || err2 != nil {
		log.Fatalf("error in pass input: passTypeId=%v, serialNum=%v", err1, err2)
	}

	// get updated pass information
	c.Header("Content-Type", "application/vnd.apple.pkpass")
}

func SetAndReturnToken(t int64) string {
	// retrieve from environment or create token for APNs
	token, err := jwt.GenerateAPNsToken(t)
	DefaultErrHandler(err)
	os.Setenv("APNsTkn", token)
	return token
}

func (e *Env) PUSHrequest(passName string) error {
	passTypeId := "pass.art4." + passName[:len(passName)-7] + ".Card" // one of categories without .pkpass extension
	fmt.Println(passTypeId)
	// retrieve from environment or create token for APNs
	token, ok := os.LookupEnv("APNsTkn")
	if !ok {
		token = SetAndReturnToken(time.Now().Unix())
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// get all devices registered for updated pass
	rows, err := e.DB.DB.Query("SELECT Device_devLibId FROM wallet.Registration WHERE Pass_passTypeId = ?", passTypeId)
	DefaultErrHandler(err)
	defer rows.Close()

	// for each device send notification to APNs
	var (
		devLibId, pushTkn string
		jsonBody          = []byte("{}")
	)
	for rows.Next() {
		if rows.Scan(&devLibId) != nil {
			log.Fatal(err)
		}
		fmt.Printf("Device Token: %v\n", devLibId)

		row := e.DB.DB.QueryRow("SELECT pushToken FROM Device WHERE deviceLibraryIdentifier = ?", devLibId)
		if row.Scan(&pushTkn) != nil {
			log.Fatal(err)
		}
		fmt.Printf("Push Token: %v\n", pushTkn)

		for { // if APNs return bad status code handle it
			req, err := http.NewRequest("POST", "https://api.push.apple.com:443/3/device/"+pushTkn, bytes.NewBuffer(jsonBody))
			DefaultErrHandler(err)

			req.Header.Add("Authorization", "bearer "+token)
			req.Header.Add("apns-topic", passTypeId)

			res, err := client.Do(req) // execute the request
			DefaultErrHandler(err)

			bodyBytes, err := ioutil.ReadAll(res.Body)
			DefaultErrHandler(err)
			body := string(bodyBytes)

			status := res.StatusCode
			switch status {
			case 200:
				fmt.Println("Ok")
			case 403: // ExpiredProviderToken, MissingProviderToken
				fmt.Println("Not Ok: " + body)
				token = SetAndReturnToken(time.Now().Unix())
			case 400:
				fmt.Println("Not Ok: " + body)
				log.Fatal("error 400")
			}

			fmt.Println("UUID", res.Header)

			if status == 200 {
				break
			}
		}
	}

	return nil
}

/*
\
Next come endpoints handlers for WEBSITE server ->
  /
*/

func GETlogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func (e *Env) POSTlogin(c *gin.Context) {
	var user classes.User
	name := c.PostForm("name")
	pass := sha256.Sum256([]byte(c.PostForm("pass")))
	err := sanitizer.CheckLoginName(name)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error in credentials": err.Error(),
		})
	}

	row := e.DB.DB.QueryRow("SELECT id FROM wallet.Staff WHERE username = ? AND pass = ?", name, fmt.Sprintf("%x", pass))
	var id int
	if row.Scan(&id) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error:": "Wrong credentials",
		})
	} else {
		user = classes.User{
			ID:   id,
			Name: name,
		}
		token, err := jwt.GenerateToken(user, JWT_TTL)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error generating token": err.Error(),
			})
		} else {
			// finaly, give user a cookie
			c.SetCookie("JWTAuth", token, JWT_TTL, "/", "5238-195-91-208-19.ngrok.io", false, true)
			c.Redirect(http.StatusFound, "/passes")
		}
	}
}

func GETpasses(c *gin.Context) {
	filesinfo, err := ioutil.ReadDir("./static/passes/current_passes")
	DefaultErrHandler(err)
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(200, "passes.html", gin.H{
		"passes": fnames,
	})
}

func GETupdate(c *gin.Context) {
	filesinfo, err := ioutil.ReadDir("./static/passes/current_passes")
	DefaultErrHandler(err)
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(200, "updatepasses.html", gin.H{
		"passes": fnames,
	})
}

func POSTupdate(c *gin.Context) {
	// get post form
	form, err := c.MultipartForm()
	DefaultErrHandler(err)

	// read passes from commit directory
	on_commit_filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	DefaultErrHandler(err)
	on_commit_fnames := make([]string, len(on_commit_filesinfo))
	for i, f := range on_commit_filesinfo {
		on_commit_fnames[i] = f.Name()
	}

	// upload only those passes that are not already in commit
	var fnames []string
	for _, fname := range AllPassnames {
		fnames = append(fnames, fname)
		for _, f := range on_commit_fnames {
			if f == fname {
				fnames = fnames[:len(fnames)-1]
			}
		}
	}

	// save them to commit directory
	for _, fname := range fnames {
		newFile := form.File[fname]
		if len(newFile) == 1 {
			err = c.SaveUploadedFile(newFile[0], "./static/passes/new_passes/"+fname)
			DefaultErrHandler(err)
		}
	}

	// redirect to commit directory
	c.Redirect(http.StatusFound, "/commit")
}

func GETcommit(c *gin.Context) {
	// read files from commit directory
	filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	DefaultErrHandler(err)
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(200, "commit.html", gin.H{
		"passes": fnames,
	})
}

func (e *Env) POSTcommit(c *gin.Context) {
	form, err := c.MultipartForm()
	DefaultErrHandler(err)

	method := form.Value["_method"][0]
	passName := form.Value["passName"][0]

	// make sure pass name is legit
	passNameLegit := false
	for _, _passName := range AllPassnames {
		if _passName == passName {
			passNameLegit = true
		}
	}

	if !passNameLegit {
		log.Fatal("error: pass name not identified")
	}

	projectDir, err := os.Getwd()
	DefaultErrHandler(err)

	switch method {
	case "post":
		timestamp := time.Now().UTC().String()
		// archive current pass
		err := os.Rename(projectDir+"/static/passes/current_passes/"+passName, projectDir+"/static/passes/old_passes/"+passName+"."+timestamp)
		DefaultErrHandler(err)
		// add new pass
		err = os.Rename(projectDir+"/static/passes/new_passes/"+passName, projectDir+"/static/passes/current_passes/"+passName)
		DefaultErrHandler(err)
		// make push request to APNs
		err = e.PUSHrequest(passName)
		DefaultErrHandler(err)
	case "delete":
		// discard the pass
		err := os.Remove(projectDir + "/static/passes/new_passes/" + passName)
		DefaultErrHandler(err)
	}

	// reload the page
	c.Redirect(http.StatusFound, "/commit")
}

func GETstats(c *gin.Context) {
	c.HTML(200, "stats.html", gin.H{})
}
