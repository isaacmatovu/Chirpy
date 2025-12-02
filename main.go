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

	"github.com/isaacmatovu/Chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

//creates a blueprint for storing our server state
type apiConfig struct{
	fileserverHits atomic.Int32
	db             *database.Queries

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
	profaneWords :=[]string{"kerfuffle","sharbert","formax"}


	//split text into words
	words:=strings.Split(text, "")

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
	return strings.Join(words,"")
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

	db,err:=sql.Open("postgres",dbUrl)
	 if err != nil {
        log.Fatal("Error opening database:", err)
    }

	dbQueries := database.New(db)
  //initialise stateful config
	apiCfg :=&apiConfig{
		//   fileserverHits: 0,
          db:             dbQueries,
	}
	//creating a router that will handle http requests
	mux:= http.NewServeMux()
//creates server configuration



//HEALTHCARE CHECKPOINT
mux.HandleFunc("GET /api/healthz",handlerReadiness)


fileserverHandler :=http.StripPrefix("/app",http.FileServer(http.Dir(".")))
//register handler to the path ,creates a file server that serves files wen somone visits that / it will look for index.html by default
// Fileserver on /app/ path
	mux.Handle("/app/",apiCfg.middlewareMetricsInc(fileserverHandler))


	//register our metrics endpoint
	mux.HandleFunc("GET /admin/metrics",apiCfg.handlerMetrics)

	//new endpoint 
	mux.HandleFunc("POST /api/validate_chirp",handleValidate)

	//register our reset endpoint
	mux.HandleFunc("POST /admin/reset",apiCfg.handlerReset)
server :=&http.Server{
		Addr: ":8080",
		Handler: mux,
	}


	fmt.Println("Server starting on http://localhost:8080")
    fmt.Println("Available endpoints:")
    fmt.Println("  GET /app/     - Serves static files (counts hits)")
    fmt.Println("  GET /admin/metrics  - Shows hit count")
    fmt.Println("  GET /admin/reset    - Resets hit counter")
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
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,"Hits counter reset to 0")
}

func handleValidate(w http.ResponseWriter,r *http.Request){

	type items struct {
		Body string `json:"body"`
	}

	
	

	decoder:=json.NewDecoder(r.Body)
	params:=items{}
	err:=decoder.Decode(&params)


	//handling parsing errors
	if err !=nil{
		respondWithError(w,http.StatusBadRequest,"Something went wrong")
		return
	}
	//validate chirp length
	if len(params.Body) > 140{
	 respondWithError(w,http.StatusBadRequest,"Chirp is too long")
		return 
	}

	  cleanedBody:=cleanProfanity(params.Body)
	//success
	respondWithJSON(w,http.StatusOK,map[string]string{
		"cleaned_body": cleanedBody,
	})
	
}