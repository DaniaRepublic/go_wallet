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
	"wallet_server/errors"
	"wallet_server/jwt"
	"wallet_server/pass_generator"
	"wallet_server/sanitizer"

	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
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

	var exists, used int
	// check if device is already registered
	row := e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from wallet.Device WHERE deviceLibraryIdentifier = ?);`, devLibId)
	if row.Scan(&exists); exists == 1 {
		log.Fatal("error: user already registered")
	}
	// check if pass exists
	row = e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from wallet.Pass WHERE serialNumber = ?)`, serialNum)
	if row.Scan(&exists); exists == 1 {
		log.Fatal("error: pass already registered")
		row = e.DB.DB.QueryRow(`SELECT used FROM Pass WHERE serialNumber = ?`, serialNum)
		row.Scan(&used)
		if used == 1 {
			log.Fatalf("error pass has been used; serialNum = %v", serialNum)
		} else {

		}
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

	lastUpdatedUnix, err := strconv.Atoi(c.Request.URL.Query().Get("passesUpdatedSince")) // should contain lastupdated tag value
	if err != nil && lastUpdatedUnix != 0 {
		log.Fatalf("error wrong update tag %v", err)
	}
	row := e.DB.DB.QueryRow("SELECT lastUpdateTag FROM PassInfo WHERE passTypeId = ?", passTypeId) // retrieve actual last update tag
	var actualLastUpdatedUnix int
	if row.Scan(&actualLastUpdatedUnix) != nil {
		log.Fatal("error geting last updated tag")
	}

	var (
		updatableSerialNums []string
		serialNum           string
	)
	// update only if last updated tag is newer
	if actualLastUpdatedUnix > lastUpdatedUnix {
		// get serial numbers of passes with larger lastupdated tags
		rows, err := e.DB.DB.Query("SELECT Pass_serialNum FROM Registration WHERE (Device_devLibId, Pass_passTypeId) = (?, ?)", devLibId, passTypeId)
		errors.DefaultErrHandler(err)
		defer rows.Close()

		for rows.Next() {
			if err = rows.Scan(&serialNum); err != nil {
				log.Fatalf("error getting serial number: %v", err.Error())
			}
			updatableSerialNums = append(updatableSerialNums, serialNum)
		}

		c.JSON(http.StatusOK, gin.H{
			"serialNumbers": updatableSerialNums,
			"lastUpdated":   strconv.Itoa(actualLastUpdatedUnix),
		})
	}
}

func (e *Env) GETupdatedpass(c *gin.Context) {
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2 := sanitizer.TestPassTypeId(passTypeId), sanitizer.TestSerialNum(serialNum)
	if err1 != nil || err2 != nil {
		log.Fatalf("error in pass input: passTypeId=%v, serialNum=%v", err1, err2)
	}

	// get updated pass information
	var exists int
	row := e.DB.DB.QueryRow("SELECT EXISTS(SELECT used FROM Pass WHERE (passTypeIdentifier, serialNumber) = (?, ?))", passTypeId, serialNum)
	if row.Scan(&exists); exists == 0 {
		log.Fatalf("error pass with passTypeId = %v , serialNum = %v doesn't exist", passTypeId, serialNum)
	}

	/*
		create new pass dynamically
	*/

	// get pass info
	var eventName, startTime, endTime string
	row = e.DB.DB.QueryRow("SELECT eventName, startTimeVal, endTimeVal FROM PassInfo WHERE passTypeId = ?", passTypeId)
	if row.Scan(&eventName, &startTime, &endTime) != nil {
		log.Fatalf("error couldn't scan PassInfo; passTypeId = %v", passTypeId)
	}

	var (
		passBytes []byte
		err       error
	)
	switch passTypeId {
	case "pass.art4.common.Card":
		passBytes, err = pass_generator.GenerateEventTicket(serialNum, eventName, startTime, endTime)
		errors.DefaultErrHandler(err)
	case "pass.art4.yearly.Card":
		break
	case "pass.art4.collectors.Card":
		break
	}

	c.Data(http.StatusOK, "application/vnd.apple.pkpass", passBytes)
}

func SetAndReturnToken(t int64) string {
	// retrieve from environment or create token for APNs
	token, err := jwt.GenerateAPNsToken(t)
	errors.DefaultErrHandler(err)
	os.Setenv("APNsTkn", token)
	return token
}

func (e *Env) PUSHrequest(passName string) error {
	passTypeId := "pass.art4." + passName[:len(passName)-7] + ".Card" // one of categories without .pkpass extension

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
	errors.DefaultErrHandler(err)
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

		row := e.DB.DB.QueryRow("SELECT pushToken FROM Device WHERE deviceLibraryIdentifier = ?", devLibId)
		if row.Scan(&pushTkn) != nil {
			log.Fatal(err)
		}

		// if APNs return bad status code handle it
		for TTL4APNsRequest := 3; TTL4APNsRequest > 0; TTL4APNsRequest-- { // to not have infinite for loop
			req, err := http.NewRequest("POST", "https://api.push.apple.com:443/3/device/"+pushTkn, bytes.NewBuffer(jsonBody))
			errors.DefaultErrHandler(err)

			req.Header.Add("Authorization", "bearer "+token)
			req.Header.Add("apns-topic", passTypeId)

			res, err := client.Do(req) // execute the request
			errors.DefaultErrHandler(err)

			bodyBytes, err := ioutil.ReadAll(res.Body)
			errors.DefaultErrHandler(err)
			body := string(bodyBytes)

			status := res.StatusCode
			switch status {
			case 200:
				fmt.Println("APNs response status: Ok")
			case 403: // ExpiredProviderToken, MissingProviderToken
				fmt.Println("APNs response status: " + body)
				token = SetAndReturnToken(time.Now().Unix())
			case 400:
				fmt.Println("APNs response status: " + body)
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
	errors.DefaultErrHandler(err)
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
	errors.DefaultErrHandler(err)
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
	errors.DefaultErrHandler(err)

	// read passes from commit directory
	on_commit_filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	errors.DefaultErrHandler(err)
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
			errors.DefaultErrHandler(err)
		}
	}

	// redirect to commit directory
	c.Redirect(http.StatusFound, "/commit")
}

func GETcommit(c *gin.Context) {
	// read files from commit directory
	filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	errors.DefaultErrHandler(err)
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
	errors.DefaultErrHandler(err)

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
	errors.DefaultErrHandler(err)

	switch method {
	case "post":
		timestamp := time.Now().UTC().String()
		// archive current pass
		err := os.Rename(projectDir+"/static/passes/current_passes/"+passName, projectDir+"/static/passes/old_passes/"+passName+"."+timestamp)
		errors.DefaultErrHandler(err)
		// add new pass
		err = os.Rename(projectDir+"/static/passes/new_passes/"+passName, projectDir+"/static/passes/current_passes/"+passName)
		errors.DefaultErrHandler(err)
		// make push request to APNs
		err = e.PUSHrequest(passName)
		errors.DefaultErrHandler(err)
	case "delete":
		// discard the pass
		err := os.Remove(projectDir + "/static/passes/new_passes/" + passName)
		errors.DefaultErrHandler(err)
	}

	// reload the page
	c.Redirect(http.StatusFound, "/commit")
}

// Add page to website
func GeneratePass(c *gin.Context) {
	_ = xid.New().String() // unique pass id
}

func GETstats(c *gin.Context) {
	c.HTML(200, "stats.html", gin.H{})
}

func GETnotfound(c *gin.Context) {
	c.HTML(404, "notfound.html", gin.H{})
}
