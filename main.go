package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/fatih/color"
	"github.com/spf13/viper"
)

var (
	googleOauthConfig      *oauth2.Config
	clientID, clientSecret string
	// red                    = color.New(color.FgRed).SprintfFunc()
	yellow = color.New(color.FgYellow).SprintfFunc()
)

func init() {

	viper.SetConfigFile("config.yml")
	err := viper.ReadInConfig()
	if err != nil {
		glog.Fatal(yellow("[GIN-debug] fatal error config file: %s", err))
	}

	clientID = viper.GetString("oauth2.providers.google.client_id")
	clientSecret = viper.GetString("oauth2.providers.google.client_secret")

	fmt.Println(clientID)
	fmt.Println(clientSecret)
}

func main() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"openid",
		},
		Endpoint: google.Endpoint,
	}

	r := gin.Default()

	r.GET("/auth/google/login", func(c *gin.Context) {
		url := googleOauthConfig.AuthCodeURL("state")
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/google/callback", func(c *gin.Context) {
		// your code to get the access token from Google
		// token := "your-access-token"

		code := c.Query("code")
		token, err := googleOauthConfig.Exchange(c, code)

		if err != nil {
			handleInternalServerError(c, err)
			return
		}

		tokenJSON, err := json.Marshal(token)

		c.SetCookie("token", string(tokenJSON), 3600, "/", "", false, true)
		c.Redirect(http.StatusMovedPermanently, "/")
	})

	r.GET("/", func(c *gin.Context) {
		marshalledToken, err := c.Cookie("token")

		if err != nil {
			handleInternalServerError(c, err)
			return
		}

		var token = new(oauth2.Token)
		if json.Unmarshal([]byte(marshalledToken), token) != nil {
			handleInternalServerError(c, err)
			return
		}
		userinfo, err := getUserInfo(c, token)
		if err != nil {
			handleInternalServerError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user": userinfo,
		})

	})

	if err := r.Run(":8080"); err != nil {
		fmt.Println(err)
	}
}

func handleInternalServerError(c *gin.Context, err error) {

	c.JSON(http.StatusInternalServerError, gin.H{
		"error": err.Error(),
	})
	c.Abort()
}

func handleBadRequest(c *gin.Context, err error) {

	c.JSON(http.StatusBadGateway, gin.H{
		"error": err.Error(),
	})
	c.Abort()
}

// func getUserInfo(token string) (*oauth2_v2.Userinfo, error) {
// 	ctx := context.Background()
// 	ts := oauth2.StaticTokenSource(
// 		&oauth2.Token{AccessToken: token},
// 	)
// 	tc := oauth2.NewClient(ctx, ts)

// 	service, err := oauth2_v2.NewService(ctx, option.WithHTTPClient(tc))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create oauth2 service: %v", err)
// 	}

// 	userInfoService := oauth2_v2.NewUserinfoService(service)
// 	userInfo, err := userInfoService.Get().Do()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get user info: %v", err)
// 	}

// 	return userInfo, nil
// }

type Userinfo struct {
	Email string `json:"email,omitempty"`

	Gender string `json:"gender,omitempty"`

	Id string `json:"id,omitempty"`

	Name string `json:"name,omitempty"`

	Picture string `json:"picture,omitempty"`
}

func getUserInfo(c *gin.Context, t *oauth2.Token) (*Userinfo, error) {
	var user = new(Userinfo)

	ctx := context.Background()
	client := googleOauthConfig.Client(ctx, t)

	userInfoUrl := "https://www.googleapis.com/oauth2/v3/userinfo"
	response, err := client.Get(userInfoUrl)
	if err != nil {
		handleInternalServerError(c, err)
	}
	defer response.Body.Close()

	decoder := json.NewDecoder(response.Body)
	decoder.Decode(user)
	return user, nil
}
