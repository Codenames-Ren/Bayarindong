package service

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"bayarindong/src/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type otpService struct {
	DB *gorm.DB
	EmailService *EmailService
}

//Random 6 Digit OTP
func OTPCode() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func hashOTP(otp string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return  string(hashedBytes), nil
}

func verifyOTP(plainOTP, hashedOTP string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedOTP), []byte(plainOTP))
	return  err == nil
}

//rate limiting otp
func (s *otpService) checkLimit(userID string, purpose string) error {
	var latestOTP models.OTP
	err := s.DB.Where("user_id = ? AND purpose = ?", userID, purpose).Order("created_at DESC").First(&latestOTP).Error;

	if err == nil && time.Since(latestOTP.CreatedAt) < time.Minute {
		return errors.New("too many request, please wait before requesting another code")
	}
	return  nil
}

//checking request
func (s *otpService) CheckMaxReq(userID string, purpose string) error {
	var count int64
	s.DB.Model(&models.OTP{}).Where("user_id = ? AND purpose = ? AND created_at >= ?", userID, purpose, time.Now().Add(-24*time.Hour)).Count(&count)

	if count >= 5 {
		var lastOTP models.OTP

		err := s.DB.Where("user_id = ? AND purpose = ? ", userID, purpose).Order("created_at DESC").First(&lastOTP).Error;
		if err != nil {
			return errors.New("failed to check otp history")
		}

		cooldown := 15 * time.Minute
		if time.Since(lastOTP.CreatedAt) < cooldown {
			remaining := cooldown - time.Since(lastOTP.CreatedAt)
			return fmt.Errorf("You have reached the maximum OTP request limit. Please wait %d minutes to request again", int(remaining.Minutes())+1)
		}
	}

	return  nil
}

//Save OTP to Database
func (s *otpService) CreateOTP(email string, purpose string) (*models.OTP, error) {
	var user models.User
	if err := s.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	if user.Email == "" {
		return nil, errors.New("user email is empty")
	}

	if err := s.checkLimit(user.ID, purpose); err != nil {
		return nil, err
	}

	if err := s.CheckMaxReq(user.ID, purpose); err != nil {
		return nil, err
	}

	plainCode := generateOTPCode()
	expiry := time.Now().Add(5 * time.Minute)

	hashedCode, err := hashOTP(plainCode)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash OTP: %w", err)
	}

	otp := &models.OTP{
		UserID: user.ID,
		Code: hashedCode,
		ExpiresAt: expiry,
		Purpose: purpose,
	}

	if err := s.DB.Create(otp).Error; err != nil {
		return nil, err
	}

	subject := "Your OTP Code"
	body := fmt.Sprintf("Hello %s, \n\nYour OTP code is: %s\n\nThis code will expire in 5 minutes. \n\nIf you did not request this, please ignore.", user.Email, plainCode)

	go func() {
		if err := s.EmailService.SendEmail(user.Email, subject, body); err != nil {
			log.Println("Failed to send otp Email : ", err)
		}
	}()

	tempOTP := &models.OTP{
		ID: otp.ID,
		UserID: otp.UserID,
		Code: plainCode,
		ExpiresAt: otp.ExpiresAt,
		Purpose: otp.Purpose,
		CreatedAt: otp.CreatedAt,
		Used: otp.Used,
	}

	return tempOTP, nil
}

func (s *otpService) verifyOTPByEmail(email, purpose, inputCode string) (bool, error) {

	//search user by email
	var user models.User
	if err := s.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return false, errors.New("user not found")
	}

	var otps []models.OTP
	err := s.DB.Where("user_id = ? AND purpose = ?", user.ID, purpose).Order("created_at DESC").Find(&otps).Error;
	if err != nil {
		return false, err
	}

	if len(otps) == 0 {
		return false, errors.New("no OTP found")
	}

	for _, otp := range otps {
		if otp.Used {
			continue
		}

		if time.Since(otp.CreatedAt) > time.Minute * 5 {
			continue
		}

		if verifyOTP(inputCode, otp.Code) {
			otp.Used = true
			s.DB.Save(&otp)

			user.Status = "active"
			s.DB.Save(&user)

			return true, nil
		}
	}

	return false, errors.New("invalid or expired otp")
}

func (s *otpService) DeleteOTP(userID, purpose string) error {
	return s.DB.Where("user_id = ? AND purpose = ?", userID, purpose).Delete(&models.OTP{}).Error
}