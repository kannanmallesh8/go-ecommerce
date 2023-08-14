package controllers

import (
	"context"
	"ecommerce/config"
	"ecommerce/database"
	"ecommerce/models"
	generate "ecommerce/tokens"
	"ecommerce/utils"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Again, global vars, try to avoid them and use dependency injection instead.
var UserCollection *mongo.Collection = database.UserData(database.Client, "Users")
var ProductCollection *mongo.Collection = database.ProductData(database.Client, "Products")
var Validate = validator.New()

type GoogleResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	Hd            string `json:"hd"`
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userpassword string, givenpassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(givenpassword), []byte(userpassword))
	valid := true
	msg := ""
	if err != nil {
		msg = "Login Or Passowrd is Incorerct"
		valid = false
	}
	return valid, msg
}

// This actually indicates that you may need to seperate your controller.go into seperate files in your controllers package.
/**********************************************************************************************/

//function to signup
//accept a post request
//POST Request
//http://localhost:8000/users/signnup
/*
   "fisrt_name":"joseph",
   "last_name":"hermis",
   "email":"something@gmail.com",
   "phone":"1156422222",
   "password":"hashed:)"

*/
func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationErr := Validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		count, err := UserCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		}
		count, err = UserCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Phone is already in use"})
			return
		}
		// It doesn't make sense to hash the password while still checking if
		// the phone number exists or not. So I moved it down a bit.
		password := HashPassword(*user.Password)
		user.Password = &password

		user.Created_At, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_At, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_ID = user.ID.Hex()
		token, refreshtoken, _ := generate.TokenGenerator(*user.Email, *user.First_Name, *user.Last_Name, user.User_ID)
		user.Token = &token
		user.Refresh_Token = &refreshtoken
		user.UserCart = make([]models.ProductUser, 0)
		user.Address_Details = make([]models.Address, 0)
		user.Order_Status = make([]models.Order, 0)
		_, inserterr := UserCollection.InsertOne(ctx, user)
		if inserterr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "not created"})
			return
		}
		defer cancel()
		c.JSON(http.StatusCreated, "Successfully Signed Up!!")
	}
}

//function to generate login and check the user to create necessary fields in the db mostly as empty array
// Accepts a POST
/*
"email":"lololol@sss.com"
"password":"coollcollcoll"

*/
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		var founduser models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := UserCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&founduser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "login or password incorrect"})
			return
		}
		PasswordIsValid, msg := VerifyPassword(*user.Password, *founduser.Password)
		defer cancel()
		if !PasswordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			fmt.Println(msg)
			return
		}
		token, refreshToken, _ := generate.TokenGenerator(*founduser.Email, *founduser.First_Name, *founduser.Last_Name, founduser.User_ID)
		defer cancel()
		generate.UpdateAllTokens(token, refreshToken, founduser.User_ID)

		// Never ever ever ever send has password or hashed password to another application!

		// In your reddit post you say you want to make sure this github repo
		// is usefull to other beginners, but these kind of mistakes only
		// makes it for other beginners more difficult to handle passwords in
		// the correct way.
		c.JSON(http.StatusOK, founduser)

	}
}

//This is function to add products
//this is an admin part
//json should look like this
// post request : http://localhost:8080/admin/addproduct
/*
json

{
"product_name" : "pencil"
"price"        : 98
"rating"       : 10
"image"        : "image-url"
}
*/
func ProductViewerAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var products models.Product
		defer cancel()
		if err := c.BindJSON(&products); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		products.Product_ID = primitive.NewObjectID()
		_, anyerr := ProductCollection.InsertOne(ctx, products)
		if anyerr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Not Created"})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, "Successfully added our Product Admin!!")
	}
}

// SearchProduct lists all the products in the database
// paging will be added and fixed soon
func SearchProduct() gin.HandlerFunc {
	return func(c *gin.Context) {
		var productlist []models.Product
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		cursor, err := ProductCollection.Find(ctx, bson.D{{}})
		if err != nil {
			c.IndentedJSON(http.StatusInternalServerError, "Someting Went Wrong Please Try After Some Time")
			return
		}
		err = cursor.All(ctx, &productlist)
		if err != nil {
			log.Println(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)
		if err := cursor.Err(); err != nil {
			// Don't forget to log errors. I log them really simple here just
			// to get the point across.
			log.Println(err)
			c.IndentedJSON(400, "invalid")
			return
		}
		defer cancel()
		c.IndentedJSON(200, productlist)

	}
}

// This is the function to search products based on alphabet name
func SearchProductByQuery() gin.HandlerFunc {
	return func(c *gin.Context) {
		var searchproducts []models.Product
		queryParam := c.Query("name")
		if queryParam == "" {
			log.Println("query is empty")
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusNotFound, gin.H{"Error": "Invalid Search Index"})
			c.Abort()
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		searchquerydb, err := ProductCollection.Find(ctx, bson.M{"product_name": bson.M{"$regex": queryParam}})
		if err != nil {
			c.IndentedJSON(404, "something went wrong in fetching the dbquery")
			return
		}
		err = searchquerydb.All(ctx, &searchproducts)
		if err != nil {
			log.Println(err)
			c.IndentedJSON(400, "invalid")
			return
		}
		defer searchquerydb.Close(ctx)
		if err := searchquerydb.Err(); err != nil {
			log.Println(err)
			c.IndentedJSON(400, "invalid request")
			return
		}
		defer cancel()
		c.IndentedJSON(200, searchproducts)
	}
}

func Callback() gin.HandlerFunc {
	return func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		var founduser models.User
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		// check is method is correct
		if r.Method != "GET" {
			c.IndentedJSON(405, "method not allowed")
			return
		}

		// get oauth state from cookie for this user
		oauthState, _ := r.Cookie("oauthstate")
		state := r.FormValue("state")
		code := r.FormValue("code")
		w.Header().Add("content-type", "application/json")

		// ERROR : Invalid OAuth State
		if state != oauthState.Value {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			fmt.Fprintf(w, "invalid oauth google state")
			return
		}

		// Exchange Auth Code for Tokens
		token, err := config.AppConfig.GoogleLoginConfig.Exchange(
			context.Background(), code)

		// ERROR : Auth Code Exchange Failed
		if err != nil {
			fmt.Fprintf(w, "falied code exchange: %s", err.Error())
			return
		}

		// Fetch User Data from google server
		response, err := http.Get(config.OauthGoogleUrlAPI + token.AccessToken)

		// ERROR : Unable to get user data from google
		if err != nil {
			fmt.Fprintf(w, "failed getting user info: %s", err.Error())
			return
		}

		// Parse user data JSON Object
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Fprintf(w, "failed read response: %s", err.Error())
			return
		}
		// send back response to browser
		fmt.Fprintln(w, string(contents))
		googleResponse := GoogleResponse{}
		err = json.Unmarshal(contents, &googleResponse)

		if err != nil {
			fmt.Fprintf(w, "failed Unmarshal response: %s", err.Error())
			return
		}

		err = UserCollection.FindOne(ctx, bson.M{"email": googleResponse.Email}).Decode(&founduser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown User SSO login"})
			return
		}

		userAccessToken, refreshToken, _ := generate.TokenGenerator(*founduser.Email, *founduser.First_Name, *founduser.Last_Name, founduser.User_ID)
		defer cancel()
		generate.UpdateAllTokens(userAccessToken, refreshToken, founduser.User_ID)
		//	utils.DeleteCookieHandler(c)
		utils.GenerateUserCookie(w, userAccessToken)
		//	utils.GetUserCookie(w)
		token1, _ := c.Cookie("token")
		fmt.Println(token1)
		//	var expiration = time.Now().Add(2 * time.Minute)

		c.SetCookie("token", userAccessToken, 2, "/", "localhost", false, true)

		c.IndentedJSON(200, string(contents))
	}
}
func GoogleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Create oauthState cookie
		oauthState := utils.GenerateStateOauthCookie(w)

		/*
			AuthCodeURL receive state that is a token to protect the user
			from CSRF attacks. You must always provide a non-empty string
			and validate that it matches the state query parameter
			on your redirect callback.
		*/
		u := config.AppConfig.GoogleLoginConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	}
}
func Encryption() gin.HandlerFunc {
	return func(c *gin.Context) {

		awsAccessKey, _ := utils.Encrypt([]byte("test data"))

		res, _ := utils.Decrypt(awsAccessKey, "Mallesh")

		res2, err := utils.Decrypt(awsAccessKey, "wdef")

		fmt.Println(res2, err)

		fmt.Println(res)
	}
}

//func GenerateCookie() gin.HandlerFunc {
//	return func(c *gin.Context) {
//		var founduser models.User
//		err := UserCollection.FindOne(ctx, bson.M{"email": googleResponse.Email}).Decode(&founduser)
//		defer cancel()
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown User SSO login"})
//			return
//		}
//
//		userAccessToken, refreshToken, _ := generate.TokenGenerator(*founduser.Email, *founduser.First_Name, *founduser.Last_Name, founduser.User_ID)
//		defer cancel()
//		generate.UpdateAllTokens(userAccessToken, refreshToken, founduser.User_ID)
//		//	utils.DeleteCookieHandler(c)
//		utils.GenerateUserCookie(w, userAccessToken)
//		//	utils.GetUserCookie(w)
//		token1, _ := c.Cookie("token")
//		fmt.Println(token1)
//		//	var expiration = time.Now().Add(2 * time.Minute)
//
//		c.SetCookie("token", userAccessToken, 2, "/", "localhost", false, true)
//
//		c.IndentedJSON(200, string(contents))
//	}
//}

/*****BLACKLIST************
func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		user_id := c.Query("id")
		if user_id == "" {
			c.Header("Content-Type", "application-json")
			c.JSON(http.StatusNoContent, gin.H{"Error": "Invalid"})
			c.Abort()
			return
		}
		usert_id, err := primitive.ObjectIDFromHex(user_id)
		if err != nil {
			c.IndentedJSON(500, "Something Went Wrong")
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		filter := bson.D{{"_id", usert_id}}
		update := bson.D{{"$unset", bson.D{{"token", ""}, {"refresh_token", ""}}}}
		_, err = UserCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			c.IndentedJSON(500, err)
		}

	}
}
//***************/
