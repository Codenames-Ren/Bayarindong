package controller

import (
	"bayarindong/src/config"
	"bayarindong/src/helper"
	"bayarindong/src/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

//register user/merchant
func RegisterInit(c *gin.Context) {
	var input struct {
		Username 	string `json:"username" binding:"required"`
		Email 		string `json:"email" binding:"required,email"`
		Password 	string `json:"password" binding:"required"`
		Role	 	string `json:"role"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//password validation
	if valid, message := helper.ValidatePassword(input.Password); !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": message})
		return
	}

	//check existing user
	var existingUser models.User
	if err := config.DB.Unscoped().Where("email = ? OR username = ?", input.Email, input.Username).First(&existingUser).Error;
	err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or Username already used"})
		return
	}

	//prefix id by role
	var prefix string
	if input.Role == "admin" {
		prefix = "ADM"
	} else {
		prefix = "MRC"
	}

	//search id by prefix
	var lastUser models.User
	var lastID string

	if err := config.DB.Unscoped().Where("id LIKE ?", prefix+"-%").Order("id DESC").First(&lastUser).Error;
	err == nil {
		lastID = lastUser.ID
	}

	//generate new ID
	newNumber := 1
	if lastID != "" {
		var lastNumber int
		if _, err := fmt.Sscanf(lastID, prefix+"-%03d", &lastNumber); err == nil {
			newNumber = lastNumber + 1
		}
	}

	//set new ID
	newUserID := fmt.Sprintf("%s-%03d", prefix, newNumber)

	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	//create temp user with pending status
	tempUser := models.User {
		ID: 					newUserID,
		Username: 				input.Username,
		Email: 					input.Email,
		Password: 				string(hashedPassword),
		Role: 					input.Role,
		Status:					"pending",
	}

	//save temp user
	if err := config.DB.Create(&tempUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temporary user"})
		return
	}

	//OTP send
	var otpErr error
	_, otpErr = otpService.CreateOTP(tempUser.Email, "registration")
	if otpErr != nil {
		config.DB.Delete(&tempUser)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate otp: ", + otpErr.Error()})
		return
	}

	c.SetCookie("registerData", newUserID, 300, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP has been sent to your email. Please verify to confirm your registration.",
		"user_id": newUserID,
	})
}