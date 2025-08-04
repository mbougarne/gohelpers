package gohelpers

import (
	"fmt"
	"os"
	"strings"
)

/*
Load all the vars in environment file to the OS environment.
It will skip the already exists env variable in the OS, thus done, by checking the var in the file if it is exists in the OS vars or not.
If We didn't provide a file, it will load the default one ".env" file in the root. This func SHOULD be called in the main func.

NOTE: this is a very simple and basic usage of loading env file data to the OS env vars. For advanced use, it's better to go with https://github.com/joho/godotenv
*/
func LoadDotEnvToOsEnv(envfile ...string) error {
	var filename string

	if len(envfile) == 0 {
		filename = defaultEnvFile()
	} else {
		filename = envfile[0]
	}

	data, err := os.ReadFile(filename)

	if err != nil {
		return err
	}

	parsedData := parseEnvData(data)
	parsedOsEnvData := parseEnvData(os.Environ())
	mapped_data := SliceStringToMapString(parsedData)
	currentEnvs := SliceStringToMapString(parsedOsEnvData, "panic")

	for key, val := range mapped_data {
		if _, ok := currentEnvs[key]; !ok {
			os.Setenv(key, val)
		}
	}

	return nil
}

/*
This is a method that return a []byte secret key to use it in JWT.
Passing a second arg as `true`, will make the func look for the `secretKeyEnvName` in the OS env vars. If that key is a custom one exists in a '.env` file, you need to load env vars to the OS first: `gohelpers.LoadDotEnvToOsEnv()`.
Using the func without a second arg, will take the `secretKeyEnvName` as input to produce a slice of bytes: []byte(secretKeyEnvName)
*/
func GenerateSecretKey(secretKeyEnvName string, envfile ...bool) ([]byte, error) {
	if len(envfile) > 0 {
		secret_key := GetEnvKey(secretKeyEnvName)

		if secret_key == "" {
			return nil, fmt.Errorf("there is no env variable with the name of '%s'", secretKeyEnvName)
		}

		return []byte(secret_key), nil
	}

	return []byte(secretKeyEnvName), nil
}

// Get environment variable from the system.
// Looking for a custom key in `.env` file, requires to load the file to the OS env vars first.
func GetEnvKey(keyName string) string {
	return os.Getenv(keyName)
}

func parseEnvData(data interface{}) []string {
	var resultSlice []string

	switch t := data.(type) {
	case []byte:
		appendToSlice(strings.Split(string(t), "\n"), &resultSlice)
	case []string:
		appendToSlice(t, &resultSlice)
	}

	return resultSlice
}

func appendToSlice(in []string, out *[]string) {
	for _, v := range in {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			continue
		}
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			continue
		}
		*out = append(*out, parts[0], parts[1])
	}
}

func defaultEnvFile() string {
	return ".env"
}
