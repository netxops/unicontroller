package model

import (
	"time"

	"gorm.io/gorm"
)

const (
	TimeFormat = "2006-01-02 15:04:05"
	DateFormat = "2006-01-02"
)

type GVA_MODEL struct {
	ID        uint           `gorm:"primarykey" mapstructure:"id"`
	CreatedAt time.Time      `mapstructure:"createdAt"`
	UpdatedAt time.Time      `mapstructure:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-" mapstructure:"deletedAt"`
}
