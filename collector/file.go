package collector

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"gopkg.in/yaml.v3"
)

func fileExists(filepath string) error {
	var err error

	fileinfo, err := os.Stat(filepath)

	if os.IsNotExist(err) {
		return err
	}

	// Return error if the fileinfo says the file path is a directory.
	if fileinfo.IsDir() {
		return &errIsDir{filepath}
	}

	return nil
}

// loadYamlFile read YAML file to byte slice than
// yaml.Unmarshal decodes the first document found within the
// in byte slice and assigns decoded values into the out value.
func loadYamlFile(filePath string, out interface{}, logger log.Logger) error {
	var err error
	var f []byte

	level.Debug(logger).Log("msg", "read YAML file", "file", filePath)

	if err := fileExists(filePath); err != nil {
		var isDirErr *errIsDir

		if os.IsNotExist(err) {
			level.Warn(logger).Log("msg", "YAML file does not exists", "error", err.Error())

			return err
		}

		if errors.As(err, &isDirErr) {
			level.Error(logger).Log("msg", "YAML path is not a file", "path", filePath, "error", err.Error())

			return err
		}
	}

	f, err = os.ReadFile(filePath)

	if err != nil {
		level.Warn(logger).Log("msg", "read file error", "error", err.Error())

		return err
	}

	if err := yaml.Unmarshal(f, out); err != nil {
		level.Error(logger).Log("msg", "error unmarshal YAML file into output struct", "file", filePath, "struct_type", fmt.Sprintf("%T", out), "error", err.Error())

		return err
	}

	return nil
}

func writeYamlFile(filePath string, in interface{}, logger log.Logger) error {
	data, err := yaml.Marshal(in)

	if err != nil {
		level.Error(logger).Log("msg", "error marshal struct to YAML", "error", err.Error())
		level.Debug(logger).Log("msg", "show struct", "struct", fmt.Sprintf("%v", in))

		return err
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		level.Error(logger).Log("msg", "error write YAML into Ceph configuration file", "error", err.Error())

		return err
	}
	return nil
}
