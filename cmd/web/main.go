package main

import (
	"log"
	"net/http"

)


var mux *http.ServeMux


func init() {

	mux = http.NewServeMux()
}

func main() {
	//oktaUtils.ParseEnvironment()

	mux.HandleFunc("/",HomeHandler )
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/sample",samplePage)
	mux.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)
	mux.HandleFunc("/profile", ProfileHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/snippet/create", createSnippet)
	mux.HandleFunc("/snippet", showSnippet)

	log.Println("Starting web server on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
