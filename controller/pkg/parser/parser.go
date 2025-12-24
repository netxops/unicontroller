package parser

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/consts"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/model"
	"github.com/influxdata/telegraf/controller/pkg/jsonc"
)

type PackageParser struct {
	schemaFileName string
	zipFilePath    string
	expectedDirs   []string
	schema         *model.Schema
	rootDir        string
}

func NewPackageParser(zipFilePath string) *PackageParser {
	return &PackageParser{
		zipFilePath:    zipFilePath,
		schemaFileName: consts.ParserSchemaFileName,
		expectedDirs: []string{
			consts.ParserApplicationDirName, consts.ParserScriptsDirName,
			consts.ParserConfDirName, consts.ParserLogsDirName,
		},
	}
}

func (p *PackageParser) Parse() error {
	r, err := zip.OpenReader(p.zipFilePath)
	if err != nil {
		return fmt.Errorf("failed to open package: %v", err)
	}
	defer func(r *zip.ReadCloser) {
		_ = r.Close()
	}(r)

	if r.File == nil || len(r.File) == 0 {
		return errors.New("invalid package structure")
	}

	if err = p.parseSchema(r); err != nil {
		return err
	}
	if err = p.checkRootDir(r); err != nil {
		return err
	}
	if err = p.checkExpectedDirs(r); err != nil {
		return err
	}
	if err = p.checkStartupScript(r); err != nil {
		return err
	}
	if err = p.checkConfigs(r); err != nil {
		return err
	}
	return nil
}

func (p *PackageParser) checkRootDir(r *zip.ReadCloser) error {
	for _, file := range r.File {
		if !p.filter(file.Name) {
			continue
		}
		rootDirName := strings.TrimSuffix(file.Name, "/")
		if rootDirName != p.schema.Package {
			continue
		}
		if !file.FileInfo().IsDir() {
			continue
		}
		p.rootDir = rootDirName
		break
	}
	if !strings.HasPrefix(p.schema.Package, consts.ParserPackPrefix) {
		return fmt.Errorf("schema file field package missing prefix: %s", consts.ParserPackPrefix)
	}
	if p.rootDir == "" || p.rootDir != p.schema.Package {
		return errors.New("package root dir name not match the schema def")
	}
	return nil
}

func (p *PackageParser) checkExpectedDirs(r *zip.ReadCloser) error {
	dirsFound := make(map[string]bool)
	for _, file := range r.File {
		dirsFound[filepath.Dir(file.Name)] = true
	}
	for _, dir := range p.expectedDirs {
		if !dirsFound[strings.Join([]string{p.rootDir, dir}, "/")] {
			return fmt.Errorf("missing or incomplete package structure: %s", dir)
		}
	}
	return nil
}

func (p *PackageParser) checkStartupScript(r *zip.ReadCloser) error {
	filesFound := make(map[string]bool)
	for _, file := range r.File {
		filesFound[file.Name] = true
	}
	fileName := strings.Join([]string{p.rootDir, consts.ParserScriptsDirName, consts.ParserStartupScriptName}, "/")
	if _, ok := filesFound[fileName]; !ok {
		return errors.New("missing startup.sh")
	}
	return nil
}

func (p *PackageParser) checkConfigs(r *zip.ReadCloser) error {
	filesFound := make(map[string]bool)
	for _, file := range r.File {
		filesFound[file.Name] = true
	}
	for _, config := range p.schema.Configs {
		if strings.TrimSpace(config.Arg) == "" || strings.TrimSpace(config.File) == "" {
			continue
		}
		fileName := strings.Join([]string{p.rootDir, consts.ParserConfDirName, config.File}, "/")
		templateFileName := fileName + ".tpl"

		if _, ok := filesFound[fileName]; !ok {
			if _, templateOk := filesFound[templateFileName]; !templateOk {
				return fmt.Errorf("missing config file: %s (or its template %s.tpl)", config.File, config.File)
			}
		}
	}
	return nil
}

func (p *PackageParser) parseSchema(r *zip.ReadCloser) error {
	for _, file := range r.File {
		if filepath.Base(file.Name) == p.schemaFileName {
			f, err := file.Open()
			if err != nil {
				return fmt.Errorf("failed the open schema file: %s", err.Error())
			}

			data, err := io.ReadAll(f)
			err = jsonc.Unmarshal(data, &p.schema)
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("failed the parse schema file: %s", err.Error())
			}
			_ = f.Close()
			break
		}
	}

	if p.schema == nil {
		return errors.New("schema file not exist or parsing failed")
	}

	if p.schema.Package == "" || p.schema.StartupMethod == "" || p.schema.Version == "" || p.schema.Desc == "" {
		return errors.New("missing or incomplete schema file params")
	}

	if p.schema.StartupMethod == consts.SystemdStartup && p.schema.Binary == "" {
		return errors.New("the binary path must not be empty when starting a service from systemd“")
	}

	return nil
}

func (p *PackageParser) SetExecPermissions() {
	if err := os.Chmod(p.BinaryPath(), 0755); err != nil {
		xlog.Error("failed to change binary permissions", xlog.FieldErr(err))
	}
}

func (p *PackageParser) UnzipToWorkspace() error {
	r, err := zip.OpenReader(p.zipFilePath)
	if err != nil {
		return fmt.Errorf("package decompression failed: %s", err.Error())
	}
	defer func(r *zip.ReadCloser) {
		_ = r.Close()
	}(r)

	for _, file := range r.File {
		if !p.filter(file.Name) {
			continue
		}
		if err = p.extractFile(file); err != nil {
			return err
		}
	}
	p.SetExecPermissions()
	return nil
}

func (p *PackageParser) PackageDIR() string {
	return filepath.Join(global.Conf.Workspace, p.schema.Package)
}

func (p *PackageParser) filter(fileName string) bool {
	return strings.HasPrefix(fileName, p.schema.Package)
}

func (p *PackageParser) extractFile(file *zip.File) error {
	filePath := filepath.Join(global.Conf.Workspace, file.Name)

	if file.FileInfo().IsDir() {
		return os.MkdirAll(filePath, os.ModePerm)
	}
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return fmt.Errorf("directory creation failed: %s", err.Error())
	}

	destFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return fmt.Errorf("file creation failed: %s", err.Error())
	}
	defer func(destFile *os.File) {
		_ = destFile.Close()
	}(destFile)

	fileInArchive, err := file.Open()
	if err != nil {
		return fmt.Errorf("package decompression failed: %s", err.Error())
	}
	defer func(fileInArchive io.ReadCloser) {
		_ = fileInArchive.Close()
	}(fileInArchive)

	if _, err = io.Copy(destFile, fileInArchive); err != nil {
		return fmt.Errorf("file write failure: %s", err.Error())
	}
	return nil
}

func (p *PackageParser) Version() string {
	return p.schema.Version
}

func (p *PackageParser) BinaryPath() string {
	return path.Join(global.Conf.Workspace, p.schema.Package, consts.ParserApplicationDirName, p.schema.Binary)
}

func (p *PackageParser) StartupScriptPath() string {
	return path.Join(global.Conf.Workspace, p.schema.Package, consts.ParserScriptsDirName, consts.ParserStartupScriptName)
}

func (p *PackageParser) Schema() *model.Schema {
	return p.schema
}

func (p *PackageParser) ConfDirPath() string {
	return path.Join(global.Conf.Workspace, p.schema.Package, consts.ParserConfDirName)
}

func (p *PackageParser) PackageName() string {
	return p.schema.Package
}

func (p *PackageParser) ListConf() (configs []string, err error) {
	confPath := path.Join(global.Conf.Workspace, p.schema.Package, consts.ParserConfDirName)
	return configs, filepath.Walk(confPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			configs = append(configs, path)
		}
		return nil
	})
}

func (p *PackageParser) UpdateConf(confPath string, update func([]byte) ([]byte, error)) error {
	content, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("file read failure: %s", err.Error())
	}
	updatedContent, err := update(content)
	if err != nil {
		return fmt.Errorf("file update failure: %s", err.Error())
	}
	err = os.WriteFile(confPath, updatedContent, os.ModePerm)
	if err != nil {
		return fmt.Errorf("file overwrite failure: %s", err)
	}
	return nil
}
