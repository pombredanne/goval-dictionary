package db

import (
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var migrated bool

// Supported DB dialects.
const (
	dialectSqlite3 = "sqlite3"
	dialectMysql   = "mysql"
)

// OvalDB is a interface of Redhat, Debian
type OvalDB interface {
	GetByPackName(string, string) ([]models.Definition, error)
	GetByCveID(string, string) ([]models.Definition, error)
	InsertFetchMeta(models.FetchMeta) error
	InsertOval(*models.Root, models.FetchMeta) error
}

// Base struct of RedHat, Debian
type Base struct {
	Family string
	DB     *gorm.DB
}

// OpenDB opens Database
func (o *Base) OpenDB() (err error) {
	if o.DB, err = gorm.Open(c.Conf.DBType, c.Conf.DBPath); err != nil {
		if c.Conf.DBType == dialectSqlite3 {
			err = fmt.Errorf("Failed to open DB. datafile: %s, err: %s", c.Conf.DBPath, err)
		} else if c.Conf.DBType == dialectMysql {
			err = fmt.Errorf("Failed to open DB, err: %s", err)
		} else {
			err = fmt.Errorf("Invalid database dialect, %s", c.Conf.DBType)
		}
		return
	}

	o.DB.LogMode(c.Conf.DebugSQL)
	if !migrated {
		if err := o.MigrateDB(); err != nil {
			return err
		}
	}
	migrated = true

	if c.Conf.DBType == dialectSqlite3 {
		if err := o.DB.Exec("PRAGMA journal_mode=WAL;").Error; err != nil {
			return err
		}
	}

	return
}

// Close close the db connection
func (o *Base) Close() error {
	if err := o.DB.Close(); err != nil {
		return fmt.Errorf("Failed to close DB. Type: %s, Path: %s, err: %s", c.Conf.DBType, c.Conf.DBPath, err)
	}
	return nil
}

// MigrateDB migrates Database
func (o *Base) MigrateDB() error {
	if err := o.DB.AutoMigrate(
		&models.FetchMeta{},
		&models.Root{},
		&models.Definition{},
		&models.Package{},
		&models.Reference{},
		&models.Advisory{},
		&models.Cve{},
		&models.Bugzilla{},
		&models.Cpe{},
		&models.Debian{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	errMsg := "Failed to create index. err: %s"
	if err := o.DB.Model(&models.Definition{}).
		AddIndex("idx_definition_root_id", "root_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := o.DB.Model(&models.Package{}).
		AddIndex("idx_packages_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Package{}).
		AddIndex("idx_packages_name", "name").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := o.DB.Model(&models.Reference{}).
		AddIndex("idx_reference_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Advisory{}).
		AddIndex("idx_advisories_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Cve{}).
		AddIndex("idx_cves_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Bugzilla{}).
		AddIndex("idx_bugzillas_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Cpe{}).
		AddIndex("idx_cpes_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Debian{}).
		AddIndex("idx_debian_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := o.DB.Model(&models.Debian{}).
		AddIndex("idx_debian_cve_id", "cve_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}

// InsertFetchMeta inserts FetchMeta
func (o Base) InsertFetchMeta(meta models.FetchMeta) error {
	tx := o.DB.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		return nil
	}

	// Update FetchMeta
	if r.RecordNotFound() {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert FetchMeta: %s", err)
		}
	} else {
		oldmeta.Timestamp = meta.Timestamp
		oldmeta.FileName = meta.FileName
		if err := tx.Save(&oldmeta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to update FetchMeta: %s", err)
		}
	}

	tx.Commit()
	return nil
}

// NewDB create a OvalDB client
func NewDB(family string) (OvalDB, error) {
	switch family {
	case c.Debian:
		return NewDebian(), nil
	case c.Ubuntu:
		return NewUbuntu(), nil
	case c.RedHat:
		return NewRedHat(), nil
	case c.Oracle:
		return NewOracle(), nil
	default:
		if strings.Contains(family, "suse") {
			suses := []string{
				c.OpenSUSE,
				c.OpenSUSELeap,
				c.SUSEEnterpriseServer,
				c.SUSEEnterpriseDesktop,
				c.SUSEOpenstackCloud,
			}
			found := false
			for _, name := range suses {
				if name == family {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("Unknown SUSE. Specify from %s: %s",
					suses, family)
			}
			return NewSUSE(family), nil
		}

		return nil, fmt.Errorf("Unknown OS Type: %s", family)
	}
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func GetByPackName(family, osVer, packName string) ([]models.Definition, error) {
	db, err := NewDB(family)
	if err != nil {
		return nil, err
	}
	return db.GetByPackName(osVer, packName)
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func GetByCveID(family, osVer, cveID string) ([]models.Definition, error) {
	db, err := NewDB(family)
	if err != nil {
		return nil, err
	}
	return db.GetByCveID(osVer, cveID)
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
