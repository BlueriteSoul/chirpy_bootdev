package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/BlueriteSoul/chirpy_bootdev/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	dev            bool
	jwtSecret      string
	polkaKey       string
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found")
	}
	dbURL := os.Getenv("DB_URL")
	myPlatform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("couldn't connect to DB")
		return
	}
	defer db.Close()
	apiCfg := apiConfig{}
	if myPlatform == "dev" {
		apiCfg.dev = true
	} else {
		apiCfg.dev = false
	}
	apiCfg.jwtSecret = os.Getenv("SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")
	apiCfg.fileserverHits.Store(0)
	apiCfg.dbQueries = database.New(db)
	mux := http.NewServeMux()
	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))
	mux.HandleFunc("GET /api/healthz", healthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByID)
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.revoke)
	mux.HandleFunc("PUT /api/users", apiCfg.changePassword)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.premiumUpgrade)

	mySrvr := http.Server{Handler: mux, Addr: ":8080"}

	err = mySrvr.ListenAndServe()
	if err != nil {
		fmt.Printf("server couldn't start")
		return
	}
	fmt.Println("server started")

}
