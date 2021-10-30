package main

import (
	//"encoding/json"
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

const (
	privKeyPath            = "keys/private.pem"
	pubKeyPath             = "keys/public.pem"
	SUPER_SUPER_SECRET_KEY = "random secret key"
	EXPIRATION_TIME        = 15
)

type userTimestamps struct {
	handleTimestamps map[string][]string
}

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

	signKey, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(signBytes, SUPER_SUPER_SECRET_KEY)
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
	User User
	jwt.StandardClaims
}

func issueTokenToUser(w http.ResponseWriter, req *http.Request) {

	s := strings.Split(req.URL.String(), "/")
	user_name := strings.Replace(s[2], "%20", " ", -1)

	if len(recordTimestamp.userTimestamps[user_name].handleTimestamps) == 0 {
		recordTimestamp.userTimestamps[user_name] = *initializeTimestamps()
	}

	authTimeStampRecord := recordTimestamp.userTimestamps[user_name].handleTimestamps
	authTimeStampRecord["auth"] = append(authTimeStampRecord["auth"], time.Now().String())

	expirationTime := time.Now().Add(EXPIRATION_TIME * time.Minute)
	claims := AccessClaims{
		User: User{user_name},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//start here

	EncodingTimeStart := time.Now()

	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		//log.Printf("Token Signing error: %v\n", err)
		return
	}

	//end here
	EncodingTimeDuration := time.Since(EncodingTimeStart)

	totalEncodingDuration += EncodingTimeDuration.Microseconds()
	totalNumberOfEncodeRequest += 1

	//creating an http cookie named token that expires in 15 min
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, tokenString)
	//change it back
	//fmt.Fprintln(w, verifyKey)
}

func verifyUser(w http.ResponseWriter, r *http.Request) {
	// check if we have a cookie named token
	tokenCookie, err := r.Cookie("token")

	switch {
	case err == http.ErrNoCookie:
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "No Token")
		return
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while Parsing cookie!")
		log.Printf("Cookie parse error: %v\n", err)
		return
	}

	// claims1 := &AccessClaims{}
	// token1, err := jwt.ParseWithClaims(tokenCookie.Value, claims1, nil)
	// u_name := claims1.User.Username

	// fmt.Println(u_name)

	// validate the token

	DecodingTimeStart := time.Now()

	claims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(tokenCookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		// verify with public key
		return verifyKey, nil
	})

	//end here
	DecodingTimeDuration := time.Since(DecodingTimeStart)
	totalDecodingDuration += DecodingTimeDuration.Microseconds()
	totalNumberOfDecodeRequest += 1

	user_name := claims.User.Username

	if len(recordTimestamp.userTimestamps) == 0 {
		recordTimestamp.userTimestamps[user_name] = *initializeTimestamps()
	}

	authTimeStampRecord := recordTimestamp.userTimestamps[user_name].handleTimestamps
	authTimeStampRecord["verify"] = append(authTimeStampRecord["verify"], time.Now().String())

	// branch out into the possible error from signing
	if err == nil {
		if !token.Valid { // but may still be invalid
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Invalid Token!")
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)

		//If token is valid sending the username back
		fmt.Fprintln(w, user_name)
	}

	if err != nil {
		switch err.(type) {

		case *jwt.ValidationError:

			vErr := err.(*jwt.ValidationError)

			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Token Expired, get a new one.")
				return

			default:
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "Error while Parsing Token!")
				//log.Printf("ValidationError error: %+v\n", vErr.Errors)
				return
			}

		default: // something else went wrong
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error while Parsing Token!")
			//log.Printf("Token parse error: %v\n", err)
			return
		}

	}

}

func publishReadme(w http.ResponseWriter, r *http.Request) {
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
	fmt.Printf("Starting LocalHost server at port 8080\n")
	http.HandleFunc("/auth/", issueTokenToUser)
	http.HandleFunc("/verify/", verifyUser)
	http.HandleFunc("/README.txt/", publishReadme)
	http.HandleFunc("/stats", releaseStats)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
