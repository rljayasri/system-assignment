package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gomarkdown/markdown"
)

/*
Defining all the constants here
*/
const (
	privKeyPath     = "keys/private.pem"
	pubKeyPath      = "keys/public.pem"
	EXPIRATION_TIME = 24 // Time in hours
)

/*
struct userTimestamps - contians member variable handleTimeStamps map for record handles auth and verify endpoints
*/

type userTimestamps struct {
	handleTimestamps map[string][]string
}

/*
struct userStat - to store userTimeStampStruct for each user
*/

type userStat struct {
	userTimestamps map[string]userTimestamps
}

var (
	verifyKey                  *rsa.PublicKey
	signKey                    *rsa.PrivateKey
	recordTimestamp            userStat
	totalEncodingDuration      int64
	totalDecodingDuration      int64
	totalNumberOfEncodeRequest int64
	totalNumberOfDecodeRequest int64
)

func initializeStat() *userStat {
	var us userStat
	us.userTimestamps = make(map[string]userTimestamps)
	return &us
}

func initializeTimestamps() *userTimestamps {
	var ust userTimestamps
	ust.handleTimestamps = make(map[string][]string)
	return &ust
}

func init() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Fatal(err)
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Fatal(err)
	}

	recordTimestamp = *initializeStat()
}

type User struct {
	Username string
}

type AccessClaims struct {
	jwt.StandardClaims
}

func issueTokenToUser(w http.ResponseWriter, req *http.Request) {

	/*
		Get the username
		Record the timestamp of auth endpoint for this User
		Add Claims and Sign Jwt with private key
		Returns the public key
	*/
	s := strings.Split(req.URL.String(), "/")
	user_name := strings.Replace(s[2], "%20", " ", -1)

	if len(recordTimestamp.userTimestamps[user_name].handleTimestamps) == 0 {
		recordTimestamp.userTimestamps[user_name] = *initializeTimestamps()
	}

	authTimeStampRecord := recordTimestamp.userTimestamps[user_name].handleTimestamps
	authTimeStampRecord["auth"] = append(authTimeStampRecord["auth"], time.Now().String())

	expirationTime := time.Now().Add(EXPIRATION_TIME * time.Hour)
	claims := AccessClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   user_name,
			ExpiresAt: expirationTime.Unix(),
		},
	}

	EncodingTimeStart := time.Now()

	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		return
	}

	EncodingTimeDuration := time.Since(EncodingTimeStart)

	totalEncodingDuration += EncodingTimeDuration.Microseconds()
	totalNumberOfEncodeRequest += 1

	//creating an http cookie named token that expires in 24 hr
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	publicKey, _ := ioutil.ReadFile(pubKeyPath)
	fmt.Fprint(w, string(publicKey[:]))
}

func verifyUser(w http.ResponseWriter, r *http.Request) {
	/*
		Get the cookie from the request
		Validate the cookie and validate the tokenString with public key
		Record the timestamp of verify endpoint for this User
		return Username
	*/

	// check if we have a cookie named token
	tokenCookie, err := r.Cookie("token")

	switch {
	case err == http.ErrNoCookie:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No Token")
		return
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while Parsing cookie!")
		log.Printf("Cookie parse error: %v\n", err)
		return
	}

	if tokenCookie.Value == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No Token")
		return
	}

	DecodingTimeStart := time.Now()

	// validate the token
	claims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(tokenCookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		// verify with public key
		return verifyKey, nil
	})

	DecodingTimeDuration := time.Since(DecodingTimeStart)
	totalDecodingDuration += DecodingTimeDuration.Microseconds()
	totalNumberOfDecodeRequest += 1

	if err != nil {

		validationError := err.(*jwt.ValidationError)

		switch validationError.Errors {
		case jwt.ValidationErrorExpired:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Bad Token or Token Expired, get a new one.")
			return

		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error while Parsing Token!")
			return
		}

	}

	if !token.Valid { // The token may still be invalid
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Token Expired, get a new one.")
		return
	}

	user_name := claims.Subject

	if len(recordTimestamp.userTimestamps) == 0 {
		recordTimestamp.userTimestamps[user_name] = *initializeTimestamps()
	}

	authTimeStampRecord := recordTimestamp.userTimestamps[user_name].handleTimestamps
	authTimeStampRecord["verify"] = append(authTimeStampRecord["verify"], time.Now().String())

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	//If token is valid sending the username back
	fmt.Fprint(w, user_name)

}

func publishReadme(w http.ResponseWriter, r *http.Request) {
	/*
		Creating a markdown file for README
		covert the markdown file to html and serving to client
	*/
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	readmeBody, err := ioutil.ReadFile("README.md")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatalf("unable to read README file: %v", err)
	}
	html := markdown.ToHTML([]byte(readmeBody), nil, nil)
	fileOut := "README.html"
	writeErr := ioutil.WriteFile(fileOut, html, 0644)

	if writeErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("could not write to readme file")
	}
	http.ServeFile(w, r, "README.html")

}

func releaseStats(w http.ResponseWriter, r *http.Request) {

	/*
		Calculate average time taken for Encoding and Decoding in Microseconds
		Send the user timestamp record for auth and verify endpoints
	*/

	if totalNumberOfEncodeRequest == 0 {
		fmt.Fprintf(w, "Average Timetaken for Encoding : No Requests Made\n")
	} else {
		AverageTimeForEncodeRequest := totalEncodingDuration / totalNumberOfEncodeRequest
		fmt.Fprintf(w, "Average Timetaken for Encoding in Microseconds : %+v\n", AverageTimeForEncodeRequest)
	}

	if totalNumberOfDecodeRequest == 0 {
		fmt.Fprintf(w, "Average Timetaken for Decoding : No Requests Made\n")
	} else {
		AverageTimeForDecodeRequest := totalDecodingDuration / totalNumberOfDecodeRequest
		fmt.Fprintf(w, "Average Timetaken for Decoding in Microseconds : %+v\n", AverageTimeForDecodeRequest)
	}

	allUserRecord := recordTimestamp.userTimestamps
	fmt.Fprintln(w, "\nPlease find the stats of all users :")
	fmt.Fprintln(w, "Logged Timestamp in chronological order")
	for k, v := range allUserRecord {

		fmt.Fprintf(w, "\nUser: %+v\n", k)
		thisUserTimestamp := v.handleTimestamps
		for handleName, v := range thisUserTimestamp {
			if strings.Compare(handleName, "auth") == 0 {
				fmt.Fprintln(w, "\n\tRequested API Service GET /auth/<username>")
				for _, eachTimestamp := range v {
					fmt.Fprintln(w, "\t"+eachTimestamp)
				}
			}
			if strings.Compare(handleName, "verify") == 0 {
				fmt.Fprintln(w, "\n\tRequested API Service GET /verify")
				for _, eachTimestamp := range v {
					fmt.Fprintln(w, "\t"+eachTimestamp)
				}

			}

		}
	}

}

func main() {
	fmt.Printf("Starting server at port 8080\n")
	http.HandleFunc("/auth/", issueTokenToUser)
	http.HandleFunc("/verify/", verifyUser)
	http.HandleFunc("/README.txt/", publishReadme)
	http.HandleFunc("/stats", releaseStats)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
