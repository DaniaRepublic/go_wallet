package endpoints

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"
	"wallet_server/classes"
	"wallet_server/dbconn"
	"wallet_server/jwt"
	gen "wallet_server/pass_generator"
	vars "wallet_server/pass_vars"
	"wallet_server/passkit"
	"wallet_server/sanitizer"

	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
)

type Env struct {
	DB *dbconn.MYSQLConn // pointer to mysql connection
}

const (
	JWT_TTL int = 2700 // 2700 seconds = 45 min
)

var (
	WEBSITE_SERV_ADDR = os.Getenv("WEBSITE_SERV_ADDR")
)

/*
\
 \
  \
   Next come endpoint handlers together with some helper functions for WALLET server ->
  /
*/

func (e *Env) POSTregister(c *gin.Context) { // new device<->token registration
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2, err3 := sanitizer.TestRegisterInput(devLibId, passTypeId, serialNum)
	if err1 != nil || err2 != nil || err3 != nil {
		c.AbortWithStatus(http.StatusBadRequest) // log.Fatal("error in register input: devLibIdError=%v, passTypeIdError=%v, serialNumError=%v", err1, err2, err3)
		return
	}

	var exists int
	// check if pass is already registered for some deviceLibraryId
	row := e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * FROM Registration WHERE Pass_serialNum = ? AND Pass_passTypeId = ?)`, serialNum, passTypeId)
	if row.Scan(&exists); exists == 1 {
		c.AbortWithStatus(http.StatusConflict) // log.Fatal("error: pass already registered")
		return
	}
	// check if pass is already in database
	// all passes should be in database before regestering
	// only GeneratePass() function is able to crate legitamate passes
	// it adds every pass it generates to database
	row = e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * FROM Pass WHERE serialNumber = ? AND passTypeIdentifier = ?)`, serialNum, passTypeId)
	if row.Scan(&exists); exists == 0 {
		c.AbortWithStatus(http.StatusConflict)
		return
	}

	// check if device is already registered
	row = e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from Device WHERE deviceLibraryIdentifier = ?)`, devLibId)
	if row.Scan(&exists); exists == 0 { // if device doesn't exist then add
		body, err := ioutil.ReadAll(c.Request.Body) // push token is in the body
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error no body pushToken: %v", err.Error())
			return
		}
		var pushTkn classes.PushTkn
		err = json.Unmarshal(body, &pushTkn)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error decoding json body")
			return
		}
		if sanitizer.TestPushToken(pushTkn.PushToken) != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// add device
		_, err = e.DB.DB.Exec("INSERT INTO Device (deviceLibraryIdentifier, pushToken) VALUES (?, ?)", devLibId, pushTkn.PushToken)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error inserting Device information: %v", err.Error())
			return
		}
	}

	// create regestration
	_, err := e.DB.DB.Exec("INSERT INTO Registration (Device_devLibId, Pass_passTypeId, Pass_serialNum) VALUES (?, ?, ?)", devLibId, passTypeId, serialNum)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error inserting Registration: %v", err.Error())
		return
	}
}

func (e *Env) DELETEregister(c *gin.Context) {
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2, err3 := sanitizer.TestRegisterInput(devLibId, passTypeId, serialNum)
	if err1 != nil || err2 != nil || err3 != nil {
		c.Abort() // log.Fatalf("error in unregister input: devLibId=%v, passTypeId=%v, serialNum=%v", err1, err2, err3)
		return
	}

	var exists int
	// check that the device is registered for that pass
	row := e.DB.DB.QueryRow(`SELECT EXISTS(SELECT * from Registration WHERE (Device_devLibId, Pass_passTypeId, Pass_serialNum) = (?, ?, ?))`, devLibId, passTypeId, serialNum)
	if row.Scan(&exists); exists == 0 {
		c.Abort() // log.Fatal("error trying to unregister device: it isn't registered")
		return
	}
	// delete regestration
	_, err := e.DB.DB.Exec("DELETE FROM Registration WHERE (Device_devLibId, Pass_passTypeId, Pass_serialNum) = (?, ?, ?)", devLibId, passTypeId, serialNum)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error deleting registration: %v", err.Error())
		return
	}

	row = e.DB.DB.QueryRow("SELECT EXISTS(SELECT * from Registration WHERE Device_devLibId = ?)", devLibId)
	if row.Scan(&exists); exists == 0 {
		// if device is not regestered for any other passes then delete it
		_, err := e.DB.DB.Exec("DELETE FROM Device WHERE deviceLibraryIdentifier = ?", devLibId)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error deleting device: %v", err.Error())
			return
		}
	}
}

func (e *Env) GETupdatablepass(c *gin.Context) {
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	err1, err2 := sanitizer.TestDevLibId(devLibId), sanitizer.TestPassTypeId(passTypeId)
	if err1 != nil || err2 != nil {
		c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error in GETupdatablepass uri: devLibId=%v, passTypeId=%v", err1, err2)
		return
	}

	providedLastUpdatedUnix, err := strconv.Atoi(c.Request.URL.Query().Get("passesUpdatedSince")) // should contain lastupdated tag value
	if err != nil && providedLastUpdatedUnix != 0 {
		c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error wrong update tag %v", err)
		return
	}
	row := e.DB.DB.QueryRow("SELECT lastUpdateTag FROM PassInfo WHERE passTypeId = ?", passTypeId) // retrieve actual last update tag
	var actualLastUpdatedUnix int
	if row.Scan(&actualLastUpdatedUnix) != nil {
		c.AbortWithStatus(http.StatusInternalServerError) // log.Fatal("error geting last updated tag")
		return
	}

	var (
		updatableSerialNums []string
		serialNum           string
	)
	// update only if last updated tag is newer
	if actualLastUpdatedUnix > providedLastUpdatedUnix {
		// get serial numbers of passes with larger lastupdated tags
		rows, err := e.DB.DB.Query("SELECT Pass_serialNum FROM Registration WHERE (Device_devLibId, Pass_passTypeId) = (?, ?)", devLibId, passTypeId)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			if err = rows.Scan(&serialNum); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error getting serial number: %v", err.Error())
				return
			}
			updatableSerialNums = append(updatableSerialNums, serialNum)
		}

		if len(updatableSerialNums) == 0 {
			c.Data(http.StatusOK, "application/json", []byte(`{"serialNumbers":[],"lastUpdated":"`+strconv.Itoa(providedLastUpdatedUnix)+`"}`))
			return
		}
		byteArr, err := json.Marshal(updatableSerialNums)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Data(http.StatusOK, "application/json", []byte(`{"serialNumbers":`+string(byteArr)+`,"lastUpdated":"`+strconv.Itoa(actualLastUpdatedUnix)+`"}`))
		return
	}

	c.Data(http.StatusOK, "application/json", []byte(`{"serialNumbers":[],"lastUpdated":"`+strconv.Itoa(providedLastUpdatedUnix)+`"}`))
}

func (e *Env) GETupdatedpass(c *gin.Context) {
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2 := sanitizer.TestPassTypeId(passTypeId), sanitizer.TestSerialNum(serialNum)
	if err1 != nil || err2 != nil {
		c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error in pass input: passTypeId=%v, serialNum=%v", err1, err2)
		return
	}

	// get updated pass information
	var exists int
	row := e.DB.DB.QueryRow("SELECT EXISTS(SELECT * FROM Pass WHERE (passTypeIdentifier, serialNumber) = (?, ?))", passTypeId, serialNum)
	if row.Scan(&exists); exists == 0 {
		c.AbortWithStatus(http.StatusBadRequest) // log.Fatalf("error pass with passTypeId = %v , serialNum = %v doesn't exist", passTypeId, serialNum)
		return
	}

	// get pass info
	var eventName, startTime, endTime string
	var lastUpdateTag int
	row = e.DB.DB.QueryRow("SELECT eventName, startTimeVal, endTimeVal, lastUpdateTag FROM PassInfo WHERE passTypeId = ?", passTypeId)
	if row.Scan(&eventName, &startTime, &endTime, &lastUpdateTag) != nil {
		c.AbortWithStatus(http.StatusInternalServerError) // log.Fatalf("error couldn't scan PassInfo; passTypeId = %v", passTypeId)
		return
	}

	var (
		passBytes []byte
		err       error
	)
	switch passTypeId {
	case "pass.art4.common.Card":
		passBytes, err = gen.GenerateEventTicket(serialNum, eventName, startTime, endTime, "common")
	case "pass.art4.yearly.Card":
		passBytes, err = gen.GenerateYearlyCard(serialNum, eventName, startTime, endTime, "yearly")
	case "pass.art4.collectors.Card":
		passBytes, err = gen.GenerateCollectorsCard(serialNum, eventName, startTime, endTime, "collectors")
	}
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Header("last-modified", strconv.Itoa(lastUpdateTag))
	c.Data(http.StatusOK, "application/vnd.apple.pkpass", passBytes)
}

func SetAndReturnToken(t int64) (string, error) {
	// retrieve from environment or create token for APNs
	token, err := jwt.GenerateAPNsToken(t)
	if err != nil {
		return "", err
	}
	os.Setenv("APNsTkn", token)
	return token, nil
}

func (e *Env) PUSHrequest(passType string) error {
	passTypeId := "pass.art4." + passType + ".Card" // one of categories without .pkpass extension
	var err error
	// retrieve from environment or create token for APNs
	token, ok := os.LookupEnv("APNsTkn")
	if !ok {
		token, err = SetAndReturnToken(time.Now().Unix())
		if err != nil {
			return err
		}
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// get all devices registered for updated pass
	rows, err := e.DB.DB.Query("SELECT Device_devLibId FROM Registration WHERE Pass_passTypeId = ?", passTypeId)
	if err != nil {
		return err
	}
	defer rows.Close()

	// for each device send notification to APNs
	var (
		devLibId, pushTkn string
		jsonBody          = []byte("{}")
	)
	for rows.Next() {
		if err = rows.Scan(&devLibId); err != nil {
			return err
		}

		row := e.DB.DB.QueryRow("SELECT pushToken FROM Device WHERE deviceLibraryIdentifier = ?", devLibId)
		if err = row.Scan(&pushTkn); err != nil {
			return err
		}

		// if APNs return bad status code handle it
		for TTL4APNsRequest := 3; TTL4APNsRequest > 0; TTL4APNsRequest-- { // to not have infinite for loop
			req, err := http.NewRequest("POST", "https://api.push.apple.com:443/3/device/"+pushTkn, bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}

			req.Header.Add("Authorization", "bearer "+token)
			req.Header.Add("apns-topic", passTypeId)

			res, err := client.Do(req) // execute the request
			if err != nil {
				return err
			}

			//bodyBytes, err := ioutil.ReadAll(res.Body)
			//if err != nil {
			//	return err
			//}
			//body := string(bodyBytes)

			status := res.StatusCode
			switch status {
			case http.StatusOK:
				// fmt.Println("APNs response status: Ok")
			case http.StatusForbidden: // ExpiredProviderToken, MissingProviderToken
				// fmt.Println("APNs response status: " + body)
				token, err = SetAndReturnToken(time.Now().Unix())
				if err != nil {
					return err
				}
			case http.StatusBadRequest:
				// fmt.Println("APNs response status: " + body)
				// log.Fatal("error 400")
			}

			//fmt.Println("UUID", res.Header)

			if status == http.StatusOK {
				break
			}
		}
	}

	return nil
}

/*
\
 \
  \
   Next come endpoint handlers together with some helper functions for WEBSITE server ->
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
			"error in credentials:": err.Error(),
		})
		return
	}

	row := e.DB.DB.QueryRow("SELECT id FROM Staff WHERE username = ? AND pass = ?", name, fmt.Sprintf("%x", pass))
	var id int
	if row.Scan(&id) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error:": "Wrong credentials",
		})
		return
	}

	user = classes.User{
		ID:   id,
		Name: name,
	}
	token, err := jwt.GenerateToken(user, JWT_TTL)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error generating token": err.Error(),
		})
		return
	}

	// finaly, give user a cookie
	c.SetCookie("JWTAuth", token, JWT_TTL, "/", WEBSITE_SERV_ADDR[8:len(WEBSITE_SERV_ADDR)-1], false, true)
	c.Redirect(http.StatusFound, "/passes")
}

func GETpasses(c *gin.Context) {
	filesinfo, err := os.ReadDir("./static/passes/current_passes")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error:": err.Error(),
		})
		return
	}
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(http.StatusOK, "passes.html", gin.H{
		"passes": fnames,
	})
}

func GETupdate(c *gin.Context) {
	filesinfo, err := os.ReadDir("./static/passes/current_passes")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error:": err.Error(),
		})
		return
	}
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fname := f.Name()
		fnames[i] = fname[:len(fname)-7] // remove .pkpass extention
	}

	c.HTML(http.StatusOK, "updatepasses.html", gin.H{
		"passes": fnames,
	})
}

func GETupdatepass(c *gin.Context) {
	passType := c.Param("passType")
	typeValid := false
	for _, category := range vars.Categories {
		if passType == category {
			typeValid = true
			break
		}
	}

	if typeValid {
		c.HTML(http.StatusOK, "updatepass.html", gin.H{
			"pass": passType,
		})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{
		"pass " + passType: "Not Found",
	})
}

func POSTupdatepass(c *gin.Context) {
	// get post form
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error posting update:": err.Error(),
		})
		return
	}

	passType := form.Value["passType"][0]
	typeValid := false
	for _, category := range vars.Categories {
		if passType == category {
			typeValid = true
			break
		}
	}
	if !typeValid {
		c.JSON(http.StatusNotFound, gin.H{
			"pass " + passType: "Not Found",
		})
		return
	}
	eventName := form.Value["eventName"][0]
	startTime := form.Value["startTime"][0]
	endTime := form.Value["endTime"][0]

	// read passes from commit directory
	on_commit_filesinfo, err := os.ReadDir("./static/passes/new_passes")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error reading passes on commit:": err.Error(),
		})
		return
	}
	for _, f := range on_commit_filesinfo {
		_fname := f.Name()
		if passType == _fname[:len(_fname)-7] { // remove .pkpass extention
			c.JSON(http.StatusOK, gin.H{
				"pass " + passType: "Already in commit. Please Remove it from commit or Commit.",
			})
			return
		}
	}

	// generate pass json file and generate pass
	switch passType {
	case "common":
		err = gen.GenerateEventTicketForCommit(eventName, startTime, endTime, passType)
	case "collectors":
		err = gen.GenerateYearlyCardForCommit(eventName, startTime, endTime, passType)
	case "yearly":
		err = gen.GenerateCollectorsCardForCommit(eventName, startTime, endTime, passType)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error creating pass:": err.Error(),
		})
		return
	}

	// redirect to commit directory
	c.Redirect(http.StatusFound, "/commit")
}

func GETcommit(c *gin.Context) {
	// read files from commit directory
	filesinfo, err := os.ReadDir("./static/passes/new_passes")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error getting files for commit:": err.Error(),
		})
		return
	}
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(http.StatusOK, "commit.html", gin.H{
		"passes": fnames,
	})
}

func (e *Env) updatePassInfoInDB(passType, projectDir string) error {
	var pass passkit.Pass
	fBytes, err := ioutil.ReadFile(projectDir + "/dyn_pass_gen/passes/" + passType + "/" + passType + ".json")
	if err != nil {
		return fmt.Errorf("error reading %v", err)
	}

	// load json into pass struct
	err = json.Unmarshal(fBytes, &pass)
	if err != nil {
		return fmt.Errorf("error unmarshaling %v", err)
	}
	eventName := pass.EventTicket.GenericPass.PrimaryFields[0].Value.(string)
	startTime := pass.EventTicket.GenericPass.SecondaryFields[0].Value.(string)
	endTime := pass.EventTicket.GenericPass.SecondaryFields[1].Value.(string)
	// update database values for that pass
	newLastUpdateTag := time.Now().Unix()
	_, err = e.DB.DB.Exec(`UPDATE PassInfo SET lastUpdateTag = ?, eventName = ?, startTimeVal = ?, endTimeVal = ? WHERE passTypeId = ?`, newLastUpdateTag, eventName, startTime, endTime, "pass.art4."+passType+".Card")
	if err != nil {
		return fmt.Errorf("error getting pass info %v", err)
	}

	return nil
}

func (e *Env) POSTcommit(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error getting commit form:": err.Error(),
		})
		return
	}

	method := form.Value["_method"][0]
	passName := form.Value["passName"][0]

	// make sure pass name is legit
	passNameLegit := false
	for _, _passName := range vars.Passnames {
		if _passName == passName {
			passNameLegit = true
		}
	}
	if !passNameLegit {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error passname not legit:": err.Error(),
		})
		return
	}

	projectDir, err := os.Getwd()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error in pwd:": err.Error(),
		})
		return
	}

	switch method {
	case "post":
		timestamp := time.Now().UTC().String()
		// archive current pass
		err := os.Rename(projectDir+"/static/passes/current_passes/"+passName, projectDir+"/static/passes/old_passes/"+passName+"."+timestamp)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error moving files:": err.Error(),
			})
			return
		}
		// add new pass
		err = os.Rename(projectDir+"/static/passes/new_passes/"+passName, projectDir+"/static/passes/current_passes/"+passName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error moving files 2:": err.Error(),
			})
			return
		}
		// update pass info in database
		passType := passName[:len(passName)-7]
		err = e.updatePassInfoInDB(passType, projectDir)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error updating pass info:": err.Error(),
			})
			return
		}
		// make push request to APNs
		err = e.PUSHrequest(passType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error pushing request to APNs:": err.Error(),
			})
			return
		}
	case "delete":
		// discard the pass
		err := os.Remove(projectDir + "/static/passes/new_passes/" + passName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error deleting file:": err.Error(),
			})
			return
		}
	}

	// reload the page
	c.Redirect(http.StatusFound, "/commit")
}

func GETgeneratable(c *gin.Context) {
	filesinfo, err := os.ReadDir("./static/passes/current_passes")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error reading current passes:": err.Error(),
		})
		return
	}
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(http.StatusOK, "generatable.html", gin.H{
		"passes": fnames,
	})
}

// function to generate a pass
func (e *Env) GeneratePass(passTypeId string) ([]byte, error) {
	var (
		passBytes []byte
		err       error
	)
	// get pass info from database
	row := e.DB.DB.QueryRow("SELECT eventName, startTimeVal, endTimeVal FROM PassInfo WHERE passTypeId = ?", passTypeId)
	var eventName, startTime, endTime string
	if err = row.Scan(&eventName, &startTime, &endTime); err != nil {
		return nil, err
	}

	serialNum := xid.New().String() // unique id for new pass
	switch passTypeId {
	case "pass.art4.common.Card":
		passBytes, err = gen.GenerateEventTicket(serialNum, eventName, startTime, endTime, "common")
	case "pass.art4.yearly.Card":
		passBytes, err = gen.GenerateYearlyCard(serialNum, eventName, startTime, endTime, "yearly")
	case "pass.art4.collectors.Card":
		passBytes, err = gen.GenerateCollectorsCard(serialNum, eventName, startTime, endTime, "collectors")
	}
	if err != nil {
		return nil, err
	}

	// insert newly created pass id into database
	_, err = e.DB.DB.Exec("INSERT INTO Pass (serialNumber, passTypeIdentifier) VALUES (?, ?)", serialNum, passTypeId)
	if err != nil {
		return nil, err
	}

	return passBytes, nil
}

// generate pass
func (e *Env) GETnewpass_from_webmanager(c *gin.Context) {
	// check pass type is valid
	passName := c.Param("passType")
	passType := passName[:len(passName)-7]
	passTypeId := "pass.art4." + passType + ".Card"
	err := sanitizer.TestPassTypeId(passTypeId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error:": "passname not legit",
		})
		return
	}

	// generate new pass
	passBytes, err := e.GeneratePass(passTypeId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error generating pass:": err.Error(),
		})
		return
	}

	c.Data(http.StatusOK, "application/zip", passBytes)
}

func GETstats(c *gin.Context) {
	c.HTML(http.StatusOK, "stats.html", gin.H{})
}

func GETnotfound(c *gin.Context) {
	c.HTML(http.StatusNotFound, "notfound.html", gin.H{})
}

/*
\
 \
  \
   Next come endpoint handlers for SIDE APIs server ->
  /
*/

// SCANNER
// ------------------------------------------------

func (e *Env) POSTscan(c *gin.Context) {
	passType := c.Param("passType")
	serialNum := c.Param("serialNumber")
	passTypeId := "pass.art4." + passType + ".Card"
	err1, err2 := sanitizer.TestPassTypeId(passTypeId), sanitizer.TestSerialNum(serialNum)
	if err1 != nil || err2 != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var exists int
	// validate that pass is reqistered
	row := e.DB.DB.QueryRow("SELECT EXISTS (SELECT * FROM Registration WHERE (Pass_passTypeId, Pass_serialNum) = (?, ?))", passTypeId, serialNum)
	if row.Scan(&exists); exists == 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// usage:
	// 0 : green (can enter)
	// 1 : yellow (check id)
	// 2 : red (can't enter)
	usage := 0
	// userName for yearly and collectors
	userName := "-"

	switch passType {
	case "common":
		var used int
		row = e.DB.DB.QueryRow("SELECT used FROM Pass WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
		row.Scan(&used)
		switch used {
		case 0:
			_, err := e.DB.DB.Exec("UPDATE Pass SET used = 1 WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		case 1:
			usage = 2
		}
	case "yearly":
		var usedThisWeek, usedThisMonth int
		row = e.DB.DB.QueryRow("SELECT usedThisWeek, usedThisMonth, userName FROM Pass WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
		row.Scan(&usedThisWeek, &usedThisMonth, &userName)
		if usedThisWeek >= 1 || usedThisMonth >= 2 {
			usage = 1
		} else {
			_, err := e.DB.DB.Exec("UPDATE Pass SET usedThisWeek = usedThisWeek+1, usedThisMonth = usedThisMonth+1 WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}
	case "collectors":
		var usedThisWeek, usedThisMonth int
		row = e.DB.DB.QueryRow("SELECT usedThisWeek, usedThisMonth, userName FROM Pass WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
		row.Scan(&usedThisWeek, &usedThisMonth, &userName)
		if usedThisWeek >= 1 || usedThisMonth >= 2 {
			usage = 1
		} else {
			_, err := e.DB.DB.Exec("UPDATE Pass SET usedThisWeek = usedThisWeek+1, usedThisMonth = usedThisMonth+1 WHERE (serialNumber, passTypeIdentifier) = (?, ?)", serialNum, passTypeId)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"userName":    userName,
		"usageStatus": usage,
		"time":        time.Now().UnixMilli(), // Moscow time
	})
}

// ------------------------------------------------

// PAYMENT SYSTEM
// ------------------------------------------------

func (e *Env) GETnewpass_from_api_call(c *gin.Context) {
	passType := c.Param("passType")
	passTypeId := "pass.art4." + passType + ".Card"
	err := sanitizer.TestPassTypeId(passTypeId)
	if err != nil {
		c.AbortWithStatus(http.StatusNotFound)
	}

	passBytes, err := e.GeneratePass(passTypeId)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	c.Data(http.StatusOK, "application/zip", passBytes)
}

// ------------------------------------------------
