package endpoints

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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

const JWT_TTL int = 1800 // 1800 seconds = 30 min

// pass names for POSTupdate handler
var AllPassnames []string = []string{
	"Collectors.pkpass",
	"Normal.pkpass",
	"Yearly.pkpass",
}

/*
\
Next come endpoints handlers for WALLET server ->
  /
*/

func (e *Env) POSTregister(c *gin.Context) { // new device<->token registration
	devLibId := c.Param("deviceLibraryIdentifier")
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2, err3 := sanitizer.TestRegisterInput(devLibId, passTypeId, serialNum)
	if err1 != nil || err2 != nil || err3 != nil {
		log.Fatalf("error in register input: devLibIdError=%v, passTypeIdError=%v, serialNumError=%v", err1, err2, err3)
	}

	// check if device is already registered
	row := e.DB.DB.QueryRow(`SELECT device_id FROM Device WHERE deviceLibraryIdentifier = ?`, devLibId)
	var devId int64
	if row.Scan(&devId) == nil {
		log.Fatal("error: user already registered")
	}
	// check if pass exists
	row = e.DB.DB.QueryRow(`SELECT pass_id FROM Pass WHERE serialNumber = ?`, serialNum)
	var passId int
	if row.Scan(&passId) != nil {
		log.Fatalf("error: pass with serialNumber: %v - doesn't exist", serialNum)
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
	res, err := e.DB.DB.Exec("INSERT INTO Device (deviceLibraryIdentifier, pushToken) VALUES (?, ?)", devLibId, pushTkn.PushToken)
	if err != nil {
		log.Fatalf("error inserting Device information: %v", err.Error())
	}
	devId, err = res.LastInsertId()
	if err != nil {
		log.Fatal(fmt.Errorf("error: user not registered"))
	}

	// create regestration
	_, err = e.DB.DB.Exec("INSERT INTO Registration (Device_id, Pass_id) VALUES (?, ?)", devId, passId)
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
	// get device and pass ids
	row := e.DB.DB.QueryRow(`SELECT Registration.Device_id, Registration.Pass_id FROM Registration
							INNER JOIN Device on Device.deviceLibraryIdentifier = ?
							INNER JOIN Pass on Pass.passTypeIdentifier = ?`, devLibId, passTypeId)
	var devId, passId int
	if row.Scan(&devId, &passId) != nil {
		log.Fatalf("error trying to unregister device: it isn't registered: %v, %v", devId, passId)
	}
	// delete regestration
	_, err := e.DB.DB.Exec("DELETE FROM Registration WHERE (Device_id, Pass_id) = (?, ?)", devId, passId)
	if err != nil {
		log.Fatalf("error deleting registration: %v", err.Error())
	}

	rows, err := e.DB.DB.Query("SELECT COUNT( * ) FROM Registration WHERE Device_id = ?", devId)
	if err != nil {
		log.Fatalf("error selecting count device: %v", err.Error())
	}
	defer rows.Close()
	var rowsNum int
	if rows.Scan(&rowsNum); rowsNum == 0 {
		// if device is not regestered for any other passes then delete it
		_, err := e.DB.DB.Exec("DELETE FROM Device WHERE device_id = ?", devId)
		if err != nil {
			log.Fatalf("error deleting device: %v", err.Error())
		}
	}
}

func (e *Env) GETupdatepass(c *gin.Context) {

}

func (e *Env) GETupdatedpass(c *gin.Context) {
	passTypeId := c.Param("passTypeIdentifier")
	serialNum := c.Param("serialNumber")
	err1, err2 := sanitizer.TestPassTypeId(passTypeId), sanitizer.TestSerialNum(serialNum)
	if err1 != nil || err2 != nil {
		log.Fatalf("error in pass input: passTypeId=%v, serialNum=%v", err1, err2)
	}

	// construct jwt

	// get updated pass information
	c.Header("Content-Type", "application/vnd.apple.pkpass")
}

func PUSHrequest(passPath, passName string) error {
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
			c.SetCookie("JWTAuth", token, JWT_TTL, "/", "b5fa-195-91-208-19.ngrok.io", false, true)
			c.Redirect(http.StatusFound, "/passes")
		}
	}
}

func GETpasses(c *gin.Context) {
	filesinfo, err := ioutil.ReadDir("./static/passes/current_passes")
	if err != nil {
		log.Fatal(err)
	}
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
	if err != nil {
		log.Fatal(err)
	}
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
	if err != nil {
		log.Fatal(err)
	}

	// read passes from commit directory
	on_commit_filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	if err != nil {
		log.Fatal(err)
	}
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
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// redirect to commit directory
	c.Redirect(http.StatusFound, "/commit")
}

func GETcommit(c *gin.Context) {
	// read files from commit directory
	filesinfo, err := ioutil.ReadDir("./static/passes/new_passes")
	if err != nil {
		log.Fatal(err)
	}
	fnames := make([]string, len(filesinfo))
	for i, f := range filesinfo {
		fnames[i] = f.Name()
	}

	c.HTML(200, "commit.html", gin.H{
		"passes": fnames,
	})
}

func POSTcommit(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		log.Fatal(err)
	}

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
	if err != nil {
		log.Fatal(err)
	}

	switch method {
	case "post":
		timestamp := time.Now().UTC().String()
		// archive current pass
		err := os.Rename(projectDir+"/static/passes/current_passes/"+passName, projectDir+"/static/passes/old_passes/"+passName+"."+timestamp)
		if err != nil {
			log.Fatal(err)
		}
		// add new pass
		err = os.Rename(projectDir+"/static/passes/new_passes/"+passName, projectDir+"/static/passes/current_passes/"+passName)
		if err != nil {
			log.Fatal(err)
		}
		// make push request to APNs
		err = PUSHrequest(projectDir+"/static/passes/current_passes/"+passName, passName)
		if err != nil {
			log.Fatal(err)
		}
	case "delete":
		// discard the pass
		err := os.Remove(projectDir + "/static/passes/new_passes/" + passName)
		if err != nil {
			log.Fatal(err)
		}
	}

	// reload the page
	c.Redirect(http.StatusFound, "/commit")
}

func GETstats(c *gin.Context) {
	c.HTML(200, "stats.html", gin.H{})
}
