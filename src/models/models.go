package models

import (
	"time"

	"gorm.io/gorm"
)

type user struct {
	ID 					string				`gorm:"primarykey"`
	Username			string				`gorm:"unique"`
	Email				string				`gorm:"unique"`
	Password			string				
	Role				string				`gorm:"default:merchant"`
	Status				string				`gorm:"default:pending"`
	CreatedAt			time.Time
	UpdatedAt			time.Time
	DeletedAt			gorm.DeletedAt		`gorm:"index"`
}