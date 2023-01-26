package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

type Response struct {
	Data string `json:"data"`
}

// api struct
type Movie struct {
	ID       string    `json:"id"`
	Isbn     string    `json:"isbn"`
	Title    string    `json:"title"`
	Director *Director `json:"director"`
}

type Director struct {
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
}

var movies []Movie

// where the JWT KEY is stored
var JwtKey = []byte(os.Getenv("JWT_KEY"))

var Users = []User{
	{
		Username: "user1",
		Password: "password1",
	},
}

func CreateToken(w http.ResponseWriter, r *http.Request) {
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
		"exp":      time.Now().Add(time.Hour * time.Duration(1)).Unix(),
	})
	tokenString, error := token.SignedString(JwtKey)
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func AllMovies(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return JwtKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(Exception{Message: "Successfully Authenticated"})
		json.NewEncoder(w).Encode(user)
		json.NewEncoder(w).Encode(movies)
		//fmt.Println(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func CreateMovie(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return JwtKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		var movie Movie
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(Exception{Message: "Successfully Authenticated"})
		json.NewEncoder(w).Encode(user)

		_ = json.NewDecoder(r.Body).Decode(&movie)
		movie.ID = strconv.Itoa(rand.Intn(100000000))
		movies = append(movies, movie)
		json.NewEncoder(w).Encode(movie)
		// json.NewEncoder(w).Encode(movies)
		//fmt.Println(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func GetMovieById(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return JwtKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User

		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(Exception{Message: "Successfully Authenticated"})
		json.NewEncoder(w).Encode(user)

		params := mux.Vars(r)

		for _, item := range movies {
			if item.ID == params["id"] {
				json.NewEncoder(w).Encode(item)
				return
			}
		}
		// json.NewEncoder(w).Encode(movies)
		//fmt.Println(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func UpdateMovie(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return JwtKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User

		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(Exception{Message: "Successfully Authenticated"})
		json.NewEncoder(w).Encode(user)

		params := mux.Vars(r)

		//loop over the movies, range
		for index, item := range movies {
			if item.ID == params["id"] {
				movies = append(movies[:index], movies[index+1:]...)
				var movie Movie
				_ = json.NewDecoder(r.Body).Decode(&movie)
				movie.ID = params["id"]
				movies = append(movies, movie)
				json.NewEncoder(w).Encode(movie)
				return
			}
		}

	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			//fmt.Println(bearerToken)
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return JwtKey, nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					next.ServeHTTP(w, r)
					//json.NewEncoder(w).Encode(Exception{Message: "Successfully Authenticated"})
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			}
			//json.NewEncoder(w).Encode(Exception{Message: "Authenticated"})

		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func main() {
	router := mux.NewRouter()

	movies = append(movies, Movie{ID: "1", Isbn: "122334", Title: "Avengers: End Game", Director: &Director{Firstname: "John", Lastname: "Kennedy"}})
	movies = append(movies, Movie{ID: "2", Isbn: "12233445", Title: "Star Wars: The Force Awakens", Director: &Director{Firstname: "Michael", Lastname: "Bay"}})
	movies = append(movies, Movie{ID: "3", Isbn: "12233446", Title: "Avengers: Infinity War", Director: &Director{Firstname: "Russo", Lastname: "Brothers"}})
	movies = append(movies, Movie{ID: "4", Isbn: "12233447", Title: "Toy Story 3", Director: &Director{Firstname: "Michael", Lastname: "Bay"}})
	movies = append(movies, Movie{ID: "5", Isbn: "12233448", Title: "Star Wars: The Last Jedi", Director: &Director{Firstname: "Michael", Lastname: "Bay"}})

	fmt.Println("Movies API with JWT Authentication")
	fmt.Println("Starting server at port 1234")
	router.HandleFunc("/register", CreateToken).Methods("POST")
	router.HandleFunc("/movies", ValidateMiddleware(AllMovies)).Methods("GET")
	router.HandleFunc("/movies/{id}", ValidateMiddleware(GetMovieById)).Methods("GET")
	router.HandleFunc("/movies", ValidateMiddleware(CreateMovie)).Methods("POST")
	router.HandleFunc("/movies/{id}", ValidateMiddleware(UpdateMovie)).Methods("PUT")

	log.Fatal(http.ListenAndServe(":12345", router))
}
