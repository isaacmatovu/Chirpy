package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/isaacmatovu/Chirpy/internal/database"
	"github.com/isaacmatovu/Chirpy/internal/external/auth"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

//creates a blueprint for storing our server state
type apiConfig struct{
	fileserverHits atomic.Int32
	db             *database.Queries
	platform        string
	jwtSecret       string
}

// User struct for JSON responses
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

// Chirp struct for JSON responses
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

//helper function for error
func respondWithError(w http.ResponseWriter,code int,msg string){
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(code)
 json.NewEncoder(w).Encode(map[string]string{
	"error" : msg,
 })
}

//helper function for JSON responses
func respondWithJSON(w http.ResponseWriter,code int,payload interface{}){
w.Header().Set("Content-Type","application/json")
w.WriteHeader(code)
json.NewEncoder(w).Encode(payload)
}

//filtering function 
func cleanProfanity(text string) string{
	//list of profane words (case-insensitive)
	profaneWords :=[]string{"kerfuffle","sharbert","fornax"}

	//split text into words by space
	words:=strings.Split(text, " ")

	//process each word
	for i,word := range words{
		lowerWord :=strings.ToLower(word)

		cleanWord := word
		for _,badWord := range profaneWords{
			if lowerWord == badWord{
				cleanWord ="****"
				break
			}
		}
		words[i] = cleanWord
	}
	return strings.Join(words," ")
}

//middleware function 
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler{
return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	cfg.fileserverHits.Add(1)
	next.ServeHTTP(w,r)
})
}

func main(){
	godotenv.Load()

	dbUrl:=os.Getenv("DB_URL")
	if dbUrl == ""{
		log.Fatal("DB_URL environment variable is not set")
	}

	platform:=os.Getenv("PLATFORM")
	if platform == ""{
		log.Fatal("PLATFORM environment variable is not set")
	}
	jwtSecret:=os.Getenv("JWT_SECRET")
	if jwtSecret ==""{
		log.Fatal("JWT_SECRET environment variable is not set")
	}
	db,err:=sql.Open("postgres",dbUrl)
	if err != nil {
        log.Fatal("Error opening database:", err)
    }

	dbQueries := database.New(db)
	//initialise stateful config
	apiCfg :=&apiConfig{
		db:       dbQueries,
		platform: platform,
		jwtSecret: jwtSecret,
	}
	
	//creating a router that will handle http requests
	mux:= http.NewServeMux()

	//HEALTHCARE CHECKPOINT
	mux.HandleFunc("GET /api/healthz",handlerReadiness)

	//get all chirps
	mux.HandleFunc("GET /api/chirps",apiCfg.handleAllChirps)

	//get a single chirp by Id
	mux.HandleFunc("GET /api/chirps/{chirpID}",apiCfg.handleGetChirp)

	//handle chirps
	mux.HandleFunc("POST /api/chirps",apiCfg.handleChirps)

	//users endpoint
	mux.HandleFunc("POST /api/users",apiCfg.handleUsers)
	
	//login endpoint
	mux.HandleFunc("POST /api/login",apiCfg.handleLogin)
	
	//refresh token endpoint
	mux.HandleFunc("POST /api/refresh",apiCfg.handleRefresh)
	
	//revoke token endpoint
	mux.HandleFunc("POST /api/revoke",apiCfg.handleRevoke)

	fileserverHandler :=http.StripPrefix("/app",http.FileServer(http.Dir(".")))
	//Fileserver on /app/ path
	mux.Handle("/app/",apiCfg.middlewareMetricsInc(fileserverHandler))

	//register our metrics endpoint
	mux.HandleFunc("GET /admin/metrics",apiCfg.handlerMetrics)

	//register our reset endpoint
	mux.HandleFunc("POST /admin/reset",apiCfg.handlerReset)

	////update user endpoint
	mux.HandleFunc("PUT /api/users",apiCfg.handleUpdateUser)
	
	server :=&http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	fmt.Println("Server starting on http://localhost:8080")
    fmt.Println("Available endpoints:")
    fmt.Println("  GET  /app/              - Serves static files (counts hits)")
    fmt.Println("  GET  /admin/metrics     - Shows hit count")
    fmt.Println("  POST /admin/reset       - Resets hit counter and deletes users (dev only)")
    fmt.Println("  POST /api/users         - Create a new user")
    fmt.Println("  POST /api/login         - Login and get tokens")
    fmt.Println("  POST /api/refresh       - Refresh access token")
    fmt.Println("  POST /api/revoke        - Revoke refresh token")
    fmt.Println("  POST /api/chirps        - Create a chirp")
    fmt.Println("  GET  /api/chirps        - Get all chirps")
    fmt.Println("  GET  /api/chirps/{id}   - Get single chirp")
    fmt.Println("  GET  /api/healthz       - Health check")
	server.ListenAndServe()
}

func handlerReadiness(w http.ResponseWriter,r *http.Request){
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter,r *http.Request){
	hits:=cfg.fileserverHits.Load()
	w.Header().Set("Content-Type","text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// Create HTML response using fmt.Sprintf with template
    html := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)
    
    fmt.Fprint(w, html)
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter,r *http.Request){
	if cfg.platform != "dev"{
		respondWithError(w,http.StatusForbidden,"Forbidden")
	    return
	}

	//delete all users
	err:=cfg.db.DeleteAllUsers(r.Context())
	if err !=nil{
		respondWithError(w,http.StatusInternalServerError,"Failed to delete users")
		return
	}

	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,"Hits counter reset to 0 and all users deleted")
}

func (cfg *apiConfig) handleUsers(w http.ResponseWriter,r *http.Request){
	type parameters struct{
		Email string `json:"email"`
		Password string `json:"password"`
	}

	decoder:=json.NewDecoder(r.Body)
	params:=parameters{}

	err:=decoder.Decode(&params)
	if err !=nil{
		respondWithError(w,http.StatusBadRequest,"Invalid request payload")
		return
	}

	//validate email
	if params.Email ==""{
		respondWithError(w,http.StatusBadRequest,"Invalid request payload")
		return
	}

	if params.Password ==""{
		respondWithError(w,http.StatusBadRequest,"password is required")
		return 
	}

	if len(params.Password) < 8{
		respondWithError(w,http.StatusBadRequest,"Password must be atleast 6 characters")
		return
	}

	//hash password 
	hashedPassword,err:=auth.HashPassword(params.Password)
	if err !=nil{
		respondWithError(w,http.StatusInternalServerError,"Failed to process password")
		return
	}
	//create user in database
	dbUser,err:=cfg.db.CreateUser(r.Context(),database.CreateUserParams{
		Email:  params.Email,
		HashedPassword:hashedPassword,
	})
	if err !=nil{
		if strings.Contains(err.Error(),"duplicate key"){
			respondWithError(w,http.StatusConflict,"Email already exists")
			return
		}
		respondWithError(w,http.StatusInternalServerError,"Failed to create user")
		return
	}

	//map database user to response
	user:=User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}

	//return user with 201 created status
	respondWithJSON(w,http.StatusCreated,user)
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter,r *http.Request){
	type LoginRequest struct{
		Email string `json:"email"`
		Password string `json:"password"`
	}

	type LoginResponse struct {
        ID           uuid.UUID `json:"id"`
        CreatedAt    time.Time `json:"created_at"`
        UpdatedAt    time.Time `json:"updated_at"`
        Email        string    `json:"email"`
        Token        string    `json:"token"`
        RefreshToken string    `json:"refresh_token"`
    }

	decoder :=json.NewDecoder(r.Body)
	params:=LoginRequest{}

	err:=decoder.Decode(&params)
	if err !=nil{
		respondWithError(w,http.StatusBadRequest,"Invalid request payload")
		return
	}

	//validate inputs
	if params.Email ==""{
		respondWithError(w,http.StatusBadRequest,"Email is required")
		return
	}

	if params.Password ==""{
		respondWithError(w,http.StatusBadRequest,"Password is required")
		return
	}

	//get user by email
	dbUser,err:=cfg.db.GetUserByEmail(r.Context(),params.Email)
	if err !=nil{
		if err ==sql.ErrNoRows{
			respondWithError(w,http.StatusUnauthorized,"Incorrect email or password")
			return 
		}
		log.Printf("Error getting user by email: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to process login")
		return
	}

	//if password hash is still the default "unset"
	if dbUser.HashedPassword =="unset"{
		respondWithError(w,http.StatusUnauthorized,"Incorrect email or password")
		return
	}

	//check password
	match,err:=auth.CheckPasswordHash(params.Password,dbUser.HashedPassword)
	if err != nil{
		log.Printf("Error checking password hash: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to process login")
		return
	}
	if !match{
		respondWithError(w,http.StatusUnauthorized,"Incorrect email or password")
		return
	}

	//create JWT token (1 hour expiration)
	token,err:=auth.MakeJWT(dbUser.ID,cfg.jwtSecret,time.Hour)
	if err !=nil{
		log.Printf("Error creating JWT: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to create token")
		return
	}

	//create refresh token
	refreshToken,err:=auth.MakeRefreshToken()
	if err !=nil{
		log.Printf("Error creating refresh token: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to create refresh token")
		return
	}

	//store refresh token in database (60 days expiration)
	now:=time.Now()
	_,err = cfg.db.CreateRefreshToken(r.Context(),database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: now,
		UpdatedAt: now,
		UserID:    dbUser.ID,
		ExpiresAt: now.Add(60 * 24 * time.Hour), // 60 days
		RevokedAt: sql.NullTime{Valid: false},   // null
	})
	if err !=nil{
		log.Printf("Error storing refresh token: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to create refresh token")
		return
	}

	//return user with both tokens
	user:=LoginResponse{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refreshToken,
	}

	respondWithJSON(w,http.StatusOK,user)
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter,r *http.Request){
	type RefreshResponse struct{
		Token string `json:"token"`
	}

	//get refresh token from header
	refreshToken,err:=auth.GetBearerToken(r.Header)
	if err !=nil{
		respondWithError(w,http.StatusUnauthorized,"Missing or invalid authorization header")
		return
	}

	//get user from refresh token
	dbUser,err:=cfg.db.GetUserFromRefreshToken(r.Context(),refreshToken)
	if err !=nil{
		if err ==sql.ErrNoRows{
			respondWithError(w,http.StatusUnauthorized,"Invalid or expired refresh token")
			return
		}
		log.Printf("Error getting user from refresh token: %v",err)
		respondWithError(w,http.StatusUnauthorized,"Invalid or expired refresh token")
		return
	}

	//create new access token (1 hour expiration)
	token,err:=auth.MakeJWT(dbUser.ID,cfg.jwtSecret,time.Hour)
	if err !=nil{
		log.Printf("Error creating JWT: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to create token")
		return
	}

	//return new access token
	respondWithJSON(w,http.StatusOK,RefreshResponse{
		Token: token,
	})
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter,r *http.Request){
	//get refresh token from header
	refreshToken,err:=auth.GetBearerToken(r.Header)
	if err !=nil{
		respondWithError(w,http.StatusUnauthorized,"Missing or invalid authorization header")
		return
	}

	//revoke the refresh token
	now:=time.Now()
	err = cfg.db.RevokeRefreshToken(r.Context(),database.RevokeRefreshTokenParams{
		Token:     refreshToken,
		RevokedAt: sql.NullTime{Time: now, Valid: true},
	})
	if err !=nil{
		log.Printf("Error revoking refresh token: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to revoke token")
		return
	}

	//return 204 no content
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleChirps(w http.ResponseWriter, r *http.Request) {
    // Extract and validate JWT token
    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
        return
    }

    // Validate the JWT and get user ID
    userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    type parameters struct {
        Body string `json:"body"`
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)

    if err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    // Validate chirp body is not empty
    if params.Body == "" {
        respondWithError(w, http.StatusBadRequest, "Chirp body cannot be empty")
        return
    }

    // Validate chirp length
    if len(params.Body) > 140 {
        respondWithError(w, http.StatusBadRequest, "Chirp is too long")
        return
    }

    // Clean profanity
    cleanedBody := cleanProfanity(params.Body)

    // Generate new UUID for chirp
    chirpID := uuid.New()
    now := time.Now()

    // Create chirp in database (using userID from JWT)
    dbChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
        ID:        chirpID,
        CreatedAt: now,
        UpdatedAt: now,
        Body:      cleanedBody,
        UserID:    userID,
    })

    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
        return
    }

    // Map database chirp to response
    chirp := Chirp{
        ID:        dbChirp.ID,
        CreatedAt: dbChirp.CreatedAt,
        UpdatedAt: dbChirp.UpdatedAt,
        Body:      dbChirp.Body,
        UserID:    dbChirp.UserID,
    }

    // Return chirp with 201 created status
    respondWithJSON(w, http.StatusCreated, chirp)
}

func (cfg *apiConfig) handleAllChirps(w http.ResponseWriter,r *http.Request){
	//get all chirps from the database
	dbChirps,err:=cfg.db.GetAllChirps(r.Context())
	if err !=nil{
		respondWithError(w,http.StatusInternalServerError,"Failed to retrieve chirps")
		return
	}

	//convert database chirps to response format
	chirps:=make([]Chirp, len(dbChirps))
	for i,dbChirp:=range dbChirps{
		chirps[i]=Chirp{
       ID : dbChirp.ID,
	   CreatedAt: dbChirp.CreatedAt,
	   UpdatedAt: dbChirp.UpdatedAt,
	   Body: dbChirp.Body,
	   UserID: dbChirp.UserID,	
		}
	}

	//return chirps with 200 ok status
	respondWithJSON(w,http.StatusOK,chirps)
}

func (cfg *apiConfig) handleGetChirp(w http.ResponseWriter,r *http.Request){
	//extract chirpID from URL PATH
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr ==""{
		respondWithError(w,http.StatusBadRequest,"Chirp ID is required")
		return
	}

	//parse chirpID TO uuid
	chirpID,err:=uuid.Parse(chirpIDStr)
	if err !=nil{
		respondWithError(w,http.StatusBadRequest,"Invalid chirp ID format")
		return
	}
	
	//get chirp from database
	dbChirp,err:=cfg.db.GetChirp(r.Context(),chirpID)
	if err !=nil{
		if err ==sql.ErrNoRows{
			respondWithError(w,http.StatusNotFound,"Chirp not found")
			return
		}
		log.Printf("Error getting chirp: %v",err)
		respondWithError(w,http.StatusInternalServerError,"Failed to retrieve chirp")
		return
	}

	//convert database Chirp to response chirp
	chirp:=Chirp{
		ID: dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body: dbChirp.Body,
		UserID: dbChirp.UserID,
	}

	respondWithJSON(w,http.StatusOK,chirp)
}

func (cfg *apiConfig) handleUpdateUser(w http.ResponseWriter,r *http.Request){

	token,err:=auth.GetBearerToken(r.Header)
	if err !=nil{
		respondWithError(w,http.StatusUnauthorized,"Missing or invalid authorization header")
		return 
	}

	userID,err :=auth.ValidateJWT(token,cfg.jwtSecret)
	if err !=nil{
		respondWithError(w,http.StatusUnauthorized,"Invalid or expired token")
		return
	}

	type UpdateUserRequest struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := UpdateUserRequest{}
	err = decoder.Decode(&params)
	if err !=nil {
		respondWithError(w,http.StatusBadRequest,"Invalid request payload")
		return 
	}

	//validate email

if params.Email == ""{
	respondWithError(w,http.StatusBadRequest,"Email is required")
	return
}

if params.Password ==""{
	respondWithError(w,http.StatusBadRequest,"Password is required")
	return
}

if len(params.Password) < 8{
	respondWithError(w,http.StatusBadRequest,"Password must be at length of 8 characters")
}

hashedPassword,err :=auth.HashPassword(params.Password)
if err !=nil{
	respondWithError(w,http.StatusInternalServerError,"Failed to process pasword")
	return
}

now :=time.Now()
dbUser,err:=cfg.db.UpdateUser(r.Context(),database.UpdateUserParams{
	ID: userID,
	Email: params.Email,
	HashedPassword:  hashedPassword,
	UpdatedAt: now,
})

if err !=nil{
	if strings.Contains(err.Error(),"duplicate key"){
		respondWithError(w,http.StatusConflict,"Email already exists")
		return
	}
	log.Printf("Error updating user: %v",err)
	respondWithError(w,http.StatusInternalServerError,"Failed to update user")
	return
}

user:=User{
	ID: dbUser.ID,
	CreatedAt: dbUser.CreatedAt,
	UpdatedAt: dbUser.UpdatedAt,
	Email: dbUser.Email,
}
respondWithJSON(w,http.StatusOK,user)
}