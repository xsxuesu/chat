package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"encoding/json"
	"log"
	"time"

	"github.com/tinode/chat/server/auth"
	_ "github.com/tinode/chat/server/auth/basic"
	"github.com/tinode/chat/server/store"
	"github.com/tinode/chat/server/store/types"
)

type vCardy struct {
	Fn    string `json:"fn"`
	Photo string `json:"photo"`
	Type  string `json:"type"`
}

type tPrivate struct {
	Comment string `json:"comment"`
}

type User struct {
	CreatedAt   string      `json:"createdAt"`
	Email       string      `json:"email"`
	Tel         string      `json:"tel"`
	AuthLevel   string      `json:"authLevel"`
	Username    string      `json:"username"`
	Password    string      `json:"passhash"`
	Private     tPrivate    `json:"private"`
	Public      vCardy      `json:"public"`
	State       int         `json:"state"`
	Status      interface{} `json:"status"`
	AddressBook []string    `json:"addressBook"`
	Tags        []string    `json:"tags"`
}

type JUser struct {
	Email       string      `json:"email"`
	Tel         string      `json:"tel"`
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	Picture     string		`json:"picture"`
	NickName    string      `json:"nickname"`
}

type ChgPwd struct {
	Username    string      `json:"username"`
	Password    string      `json:"password"`
}

type ReturnInfo struct {
	Success bool `json:"success"`
	Info 	string `json:"info"`
}

func RegisterUser(wrt http.ResponseWriter, r *http.Request) {
	var jUser JUser
	info := ReturnInfo{}
	info.Success = true

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		info.Success = false
		info.Info = err.Error()
	}
	if err := r.Body.Close(); err != nil {
		info.Success = false
		info.Info = err.Error()
	}
	if err := json.Unmarshal(body, &jUser); err != nil {
		info.Success = false
		info.Info = err.Error()
	}else{
		if jUser.Username == "" || jUser.Password == "" || jUser.NickName == "" {
			info.Success = false
			info.Info = "username , password and nickname can't empty"
		}
	}

	if msg ,err := RegisterToDb(jUser); err != nil {
		info.Success = false
		info.Info = err.Error()
	}else{
		info.Info = msg
	}
	ReturnW(wrt,info)
	return
}

func ChangePassword(wrt http.ResponseWriter, r *http.Request) {
	var pwd ChgPwd
	info := ReturnInfo{}
	info.Success = true

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		info.Success = false
		info.Info = err.Error()
	}
	if err := r.Body.Close(); err != nil {
		info.Success = false
		info.Info = err.Error()
	}
	if err := json.Unmarshal(body, &pwd); err != nil {
		info.Success = false
		info.Info = err.Error()
	}else{
		if pwd.Username == "" || pwd.Password == "" {
			info.Success = false
			info.Info = "username and password can't empty"
		}
	}

	if msg ,err := ChangePwd(pwd); err != nil {
		info.Success = false
		info.Info = err.Error()
	}else{
		info.Info = msg
	}
	ReturnW(wrt,info)
	return
}


func ReturnW(wrt http.ResponseWriter,info ReturnInfo)  {
	wrt.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if info.Success==true{
		wrt.WriteHeader(http.StatusOK)
	}else{

		fmt.Println("info.Info:",info.Info)
		wrt.WriteHeader(http.StatusAlreadyReported) // unprocessable entity
	}

	body , _ := json.Marshal(info)

	wrt.Write(body)
	return
}

func ChangePwd(pwd ChgPwd)(string,error){
	uid,err := store.Users.GetUId(pwd.Username)
	if err != nil {
		return "the user not exist!",err
	}

	if uid == 0 {
		return "the user not exist!",fmt.Errorf("the %s user not exist!",pwd.Username)
	}

	authHandler := store.GetAuthHandler("basic")
	authHandler.Init(`{"add_to_tags"：true,"min_password_length":6,"min_login_length":3}`,pwd.Username)
	authLevel := auth.LevelAuth
	secret := []byte(pwd.Username+":"+pwd.Password)
	if _, err := authHandler.UpdateRecord(&auth.Rec{Uid:uid, AuthLevel: authLevel},
		 secret); err != nil {
		return "",err
	}

	return ""+ pwd.Username+" had change password",nil
}

func RegisterToDb(jUser JUser) (string,error) {
	user := types.User{
		State: 1,
		Access: types.DefaultAccess{
			Auth: types.ModeCAuth,
			Anon: types.ModeNone,
		},
		Public: &vCardy{Fn:jUser.NickName},
	}

	user.CreatedAt = getCreatedTime("-1h")

	user.Tags = make([]string, 0)
	user.Tags = append(user.Tags, "basic:"+jUser.Username)
	if jUser.Email != "" {
		user.Tags = append(user.Tags, "email:"+jUser.Email)
	}
	if jUser.Tel != "" {
		user.Tags = append(user.Tags, "tel:"+jUser.Tel)
	}

	// store.Users.Create will subscribe user to !me topic but won't create a !me topic
	if _, err := store.Users.Create(&user, nil); err != nil {
		return "",err
	}

	// Save credentials: email and phone number as if they were confirmed.
	if jUser.Email != "" {
		if _, err := store.Users.UpsertCred(&types.Credential{
			User:   user.Id,
			Method: "email",
			Value:  jUser.Email,
			Done:   true,
		}); err != nil {
			return "",err
		}
	}
	if jUser.Tel != "" {
		if _, err := store.Users.UpsertCred(&types.Credential{
			User:   user.Id,
			Method: "tel",
			Value:  jUser.Tel,
			Done:   true,
		}); err != nil {
			return "",err
		}
	}

	authLevel := auth.LevelAuth

	// Add authentication record
	authHandler := store.GetAuthHandler("basic")
	passwd := jUser.Password

	if _, err := authHandler.AddRecord(&auth.Rec{Uid: user.Uid(), AuthLevel: authLevel},
		[]byte(jUser.Username+":"+passwd)); err != nil {

		return "",err
	}
	return fmt.Sprintf("usr;" + jUser.Username + ";" + user.Uid().UserId() + "; had registered" ),nil
}


func getCreatedTime(delta string) time.Time {
	dd, err := time.ParseDuration(delta)
	if err != nil && delta != "" {
		log.Fatal("Invalid duration string", delta)
	}
	return time.Now().UTC().Round(time.Millisecond).Add(dd)
}