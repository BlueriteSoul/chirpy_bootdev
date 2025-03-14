package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/BlueriteSoul/chirpy_bootdev/internal/auth"
	"github.com/BlueriteSoul/chirpy_bootdev/internal/database"
	"github.com/google/uuid"
)

var badWords = map[string]struct{}{
	"kerfuffle": {},
	"sharbert":  {},
	"fornax":    {},
}

func healthz(w http.ResponseWriter, r *http.Request) {
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) metrics(w http.ResponseWriter, r *http.Request) {
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write([]byte(fmt.Sprintf(`<html>
		<body>
		  <h1>Welcome, Chirpy Admin</h1>
		  <p>Chirpy has been visited %d times!</p>
		</body>
	  </html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	if !cfg.dev {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	cfg.fileserverHits.Store(0)
	err := cfg.dbQueries.DropAllUsers(context.Background())
	if err != nil {
		log.Printf("Couldn't reset users: %s", err)
		return
	}
	err = cfg.dbQueries.DropAllChirps(context.Background())
	if err != nil {
		log.Printf("Couldn't reset chirps: %s", err)
		return
	}
	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
	type Chirp struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	chirp := Chirp{}
	err := decoder.Decode(&chirp)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	// params is a struct with data populated successfully
	if len(chirp.Body) > 140 {
		type returnVals struct {
			// the key will be the name of struct field unless you give it an explicit JSON tag
			Error string `json:"error"`
		}
		respBody := returnVals{
			Error: "Chirp is too long",
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
	} else {
		var rebuiltStr string
		for _, word := range strings.Split(chirp.Body, " ") {
			if _, exists := badWords[strings.ToLower(word)]; exists {
				rebuiltStr += "**** "
			} else {
				rebuiltStr += word + " "
			}
		}
		rebuiltStr = rebuiltStr[:len(rebuiltStr)-1]
		type returnVals struct {
			CleanedBody string `json:"cleaned_body"`
		}
		respBody := returnVals{CleanedBody: rebuiltStr}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	}
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type Usr struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	usr := Usr{}
	err := decoder.Decode(&usr)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	// params is a struct with data populated successfully
	hashPass, err := auth.HashPassword(usr.Password)
	if err != nil {
		log.Printf("Couldn't hash the password: %s", err)
		w.WriteHeader(500)
		return
	}
	dbUsr, err := cfg.dbQueries.CreateUser(context.Background(), database.CreateUserParams{HashedPassword: hashPass, Email: usr.Email})
	if err != nil {
		log.Printf("Couldn't create a user in DB: %v", err)
		w.WriteHeader(500)
		return
	}
	type returnVals struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	respBody := returnVals{ID: dbUsr.ID, CreatedAt: dbUsr.CreatedAt, UpdatedAt: dbUsr.UpdatedAt, Email: dbUsr.Email, IsChirpyRed: dbUsr.IsChirpyRed}
	dat, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	type Chrp struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Body  string    `json:"body"`
		UsrID uuid.UUID `json:"user_id"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting the bearer token: %v", err)
		w.WriteHeader(500)
		return
	}
	tkUsr, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Error validating user: %v", err)
		w.WriteHeader(401)
		return
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	chrp := Chrp{}
	err = decoder.Decode(&chrp)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	// params is a struct with data populated successfully
	var rebuiltStr string
	if len(chrp.Body) > 140 {
		type returnVals struct {
			// the key will be the name of struct field unless you give it an explicit JSON tag
			Error string `json:"error"`
		}
		respBody := returnVals{
			Error: "Chirp is too long",
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(dat)
	} else {

		for _, word := range strings.Split(chrp.Body, " ") {
			if _, exists := badWords[strings.ToLower(word)]; exists {
				rebuiltStr += "**** "
			} else {
				rebuiltStr += word + " "
			}
		}
		rebuiltStr = rebuiltStr[:len(rebuiltStr)-1]
	}
	fmt.Print(chrp.UsrID)
	dbChrp, err := cfg.dbQueries.CreateChirp(context.Background(), database.CreateChirpParams{Body: rebuiltStr, UserID: tkUsr})
	if err != nil {
		log.Printf("Couldn't create a chirp in DB: %v", err)
		w.WriteHeader(500)
		return
	}
	type returnVals2 struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	respBody2 := returnVals2{ID: dbChrp.ID, CreatedAt: dbChrp.CreatedAt, UpdatedAt: dbChrp.UpdatedAt, Body: dbChrp.Body, UserID: dbChrp.UserID}
	dat, err := json.Marshal(respBody2)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	authorIDstr := r.URL.Query().Get("author_id")
	sortMode := r.URL.Query().Get("sort")
	var authorID uuid.UUID
	var err666 error
	if authorIDstr != "" {
		authorID, err666 = uuid.Parse(authorIDstr)
		if err666 != nil {
			log.Printf("Couldn't parse UUID: %v", err666)
			w.WriteHeader(404)
			return
		}
	}

	if authorID != uuid.Nil {
		chrps, err := cfg.dbQueries.GetAllChirpsForAuthor(context.Background(), authorID)
		if err != nil {
			log.Printf("Couldn't get chirps from DB: %v", err)
			w.WriteHeader(404)
			return
		}
		if sortMode == "desc" {
			sort.Slice(chrps, func(i, j int) bool {
				return chrps[i].CreatedAt.After(chrps[j].CreatedAt)
			})
		}
		type returnVals struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}
		retChrps := make([]returnVals, len(chrps))
		for i, chrp := range chrps {
			retChrps[i] = returnVals{ID: chrp.ID, CreatedAt: chrp.CreatedAt, UpdatedAt: chrp.UpdatedAt, Body: chrp.Body, UserID: chrp.UserID}
		}
		dat, err := json.Marshal(retChrps)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		// 1. Set the Content-Type header
		w.Header().Set("Content-Type", "application/json")

		// 2. Write a status code (200 OK)
		w.WriteHeader(http.StatusOK)

		// 3. Write the response body
		w.Write(dat)
		return
	}
	chrps, err := cfg.dbQueries.GetAllChirps(context.Background())
	if err != nil {
		log.Printf("Couldn't get chirps from DB: %v", err)
		w.WriteHeader(404)
		return
	}
	if sortMode == "desc" {
		sort.Slice(chrps, func(i, j int) bool {
			return chrps[i].CreatedAt.After(chrps[j].CreatedAt)
		})
	}
	type returnVals struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	retChrps := make([]returnVals, len(chrps))
	for i, chrp := range chrps {
		retChrps[i] = returnVals{ID: chrp.ID, CreatedAt: chrp.CreatedAt, UpdatedAt: chrp.UpdatedAt, Body: chrp.Body, UserID: chrp.UserID}
	}
	dat, err := json.Marshal(retChrps)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write(dat)
}

func (cfg *apiConfig) getChirpByID(w http.ResponseWriter, r *http.Request) {
	chirpIDstr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDstr)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	chrp, err := cfg.dbQueries.GetChirpByID(context.Background(), chirpID)
	if err != nil {
		log.Printf("Couldn't get chirps from DB: %v", err)
		w.WriteHeader(404)
		return
	}
	type returnVals struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	retChrp := returnVals{ID: chrp.ID, CreatedAt: chrp.CreatedAt, UpdatedAt: chrp.UpdatedAt, Body: chrp.Body, UserID: chrp.UserID}

	dat, err := json.Marshal(retChrp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write(dat)
}

func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	type Usr struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"` // Using pointer to make it optional
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	usr := Usr{}
	err := decoder.Decode(&usr)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	// params is a struct with data populated successfully
	dbUsr, err := cfg.dbQueries.GetUserByEmail(context.Background(), usr.Email)
	if err != nil {
		log.Printf("Couldn't reach DB for user: %s", err)
		w.WriteHeader(500)
		return
	}
	if auth.CheckPasswordHash(usr.Password, dbUsr.HashedPassword) == nil {
		type returnVals struct {
			ID           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
			IsChirpyRed  bool      `json:"is_chirpy_red"`
		}
		const oneHourInSeconds = 60 * 60
		expiresInSeconds := oneHourInSeconds // Default: 1 hour

		if usr.ExpiresInSeconds != nil {
			// If client specified a value
			requestedSeconds := *usr.ExpiresInSeconds

			if requestedSeconds > 0 && requestedSeconds <= oneHourInSeconds {
				// If requested time is positive and not more than 1 hour
				expiresInSeconds = requestedSeconds
			}
			// Otherwise, keep the default 1 hour
		}

		// Create JWT token with the appropriate expiration
		expirationTime := time.Duration(expiresInSeconds) * time.Second
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			// Handle error
			log.Printf("Couldn't create refresh token: %v", err)
			w.WriteHeader(500)
			return
		}
		_, err = cfg.dbQueries.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{Token: refreshToken, UserID: dbUsr.ID, ExpiresAt: time.Now().Add(60 * 24 * time.Hour)})
		if err != nil {
			// Handle error
			log.Printf("Couldn't store refresh token in DB: %v", err)
			w.WriteHeader(500)
			return
		}
		// Generate token (you'll need to implement this using a JWT library)
		token, err := auth.MakeJWT(dbUsr.ID, cfg.jwtSecret, expirationTime)
		if err != nil {
			// Handle error
			log.Printf("Couldn't create JWT: %v", err)
			w.WriteHeader(500)
			return
		}
		respBody := returnVals{ID: dbUsr.ID, CreatedAt: dbUsr.CreatedAt, UpdatedAt: dbUsr.UpdatedAt, Email: dbUsr.Email, Token: token, RefreshToken: refreshToken, IsChirpyRed: dbUsr.IsChirpyRed}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	} else {
		log.Printf("Email or password don't match: %s", err)
		w.WriteHeader(401)
		return
	}
}

func (cfg *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Couldn't get bearer token: %v", err)
		w.WriteHeader(500)
		return
	}
	user, err := cfg.dbQueries.GetUserFromRefreshToken(context.Background(), token)
	if err != nil {
		log.Printf("Couldn't match token with user: %v", err)
		w.WriteHeader(401)
		return
	}

	_, err = cfg.dbQueries.GetRefreshToken(context.Background(), user.ID)
	if err != nil {
		log.Printf("Refresh token missing/expired (possible db error): %v", err)
		w.WriteHeader(401)
		return
	}
	type returnVals struct {
		Token string `json:"token"`
	}
	retJWToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		log.Printf("Couldn't create JWToken: %v", err)
		w.WriteHeader(500)
		return
	}
	retTok := returnVals{Token: retJWToken}

	dat, err := json.Marshal(retTok)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// 2. Write a status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// 3. Write the response body
	w.Write(dat)
}

func (cfg *apiConfig) revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Couldn't get bearer token: %v", err)
		w.WriteHeader(500)
		return
	}
	user, err := cfg.dbQueries.GetUserFromRefreshToken(context.Background(), token)
	if err != nil {
		log.Printf("Couldn't match token with user: %v", err)
		w.WriteHeader(500)
		return
	}

	err = cfg.dbQueries.RevokeToken(context.Background(), user.ID)
	if err != nil {
		log.Printf("Couldn't revoke token: %v", err)
		w.WriteHeader(500)
		return
	}
	// 1. Set the Content-Type header
	w.Header().Set("Content-Type", "application/json")
	// 2. Write a status code (200 OK)
	w.WriteHeader(204)
}

func (cfg *apiConfig) changePassword(w http.ResponseWriter, r *http.Request) {
	type Usr struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Couldn't get bearer token: %v", err)
		w.WriteHeader(401)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Couldn't validate JWT: %v", err)
		w.WriteHeader(401)
		return
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	usr := Usr{}
	err = decoder.Decode(&usr)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	hashPass, err := auth.HashPassword(usr.Password)
	if err != nil {
		log.Printf("Couldn't hash the password: %s", err)
		w.WriteHeader(500)
		return
	}
	dbUsr, err := cfg.dbQueries.UpdatePasswordAndEmail(context.Background(), database.UpdatePasswordAndEmailParams{HashedPassword: hashPass, Email: usr.Email, ID: userID})
	if err != nil {
		log.Printf("Couldn't update password: %v", err)
		w.WriteHeader(500)
		return
	}
	type returnVals struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	respBody := returnVals{ID: dbUsr.ID, CreatedAt: dbUsr.CreatedAt, UpdatedAt: dbUsr.UpdatedAt, Email: dbUsr.Email}
	dat, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDstr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDstr)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting the bearer token: %v", err)
		w.WriteHeader(401)
		return
	}
	tokUserID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Error validating user: %v", err)
		w.WriteHeader(401)
		return
	}
	chirp, err := cfg.dbQueries.GetChirpByID(context.Background(), chirpID)
	if err != nil {
		log.Printf("Chirp not found: %v", err)
		w.WriteHeader(404)
		return
	}
	if chirp.UserID != tokUserID {
		log.Printf("author and chirp don't match: %v", err)
		w.WriteHeader(403)
		return
	}
	err = cfg.dbQueries.DeleteChirp(context.Background(), chirpID)
	if err != nil {
		log.Printf("Couldn't delete the chirp: %v", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(204)
}

func (cfg *apiConfig) premiumUpgrade(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIPolkaKey(r.Header)
	if err != nil {
		log.Printf("Wrong format polka keys: %v", err)
		w.WriteHeader(401)
		return
	}
	if apiKey != cfg.polkaKey {
		log.Printf("Wrong polka keys: %v", err)
		w.WriteHeader(401)
		return
	}
	type WebhookRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	webhookReq := WebhookRequest{}
	err = decoder.Decode(&webhookReq)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %v", err)
		w.WriteHeader(500)
		return
	}
	if webhookReq.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	userID, err := uuid.Parse(webhookReq.Data.UserID)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	_, err = cfg.dbQueries.GetUserByID(context.Background(), userID)
	if err != nil {
		log.Printf("Couldn't get user from DB: %v", err)
		w.WriteHeader(404)
		return
	}
	_, err = cfg.dbQueries.UpgradeToChirpyRed(context.Background(), userID)
	if err != nil {
		log.Printf("Couldn't upgrade user to premium: %v", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(204)
}
