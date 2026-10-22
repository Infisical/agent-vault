package store

import (
	"fmt"

	"gorm.io/gorm"
)

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		var count int64
		if err := db.Table("upstream_proxies").Where("is_default = ?", true).Count(&count).Error; err != nil {
			return fmt.Errorf("checking upstream proxy defaults: %w", err)
		}
		if count > 1 {
			return fmt.Errorf("cannot enforce single upstream proxy default: found %d defaults; choose one manually", count)
		}
		return db.Exec(`CREATE UNIQUE INDEX upstream_proxies_single_default
			ON upstream_proxies (is_default) WHERE is_default = TRUE`).Error
	})
}
