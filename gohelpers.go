package gohelpers

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func VerifyHashedPassword(plain, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	return err == nil
}

func StructToMap(in any) map[string]any {
	reflectedStruct := reflect.ValueOf(in)
	fieldsLength := reflectedStruct.NumField()
	resultMap := make(map[string]interface{}, fieldsLength)

	for i := 0; i < fieldsLength; i++ {
		resultMap[strings.ToLower(reflectedStruct.Type().Field(i).Name)] = reflectedStruct.Field(i).Interface()
	}

	return resultMap
}

func RemoveFieldFromStruct(in any, field string) (map[string]string, error) {
	mapResult := make(map[string]string)
	tempMap := make(map[string]interface{})

	b, marshal_err := json.Marshal(&in)

	if marshal_err != nil {
		return nil, marshal_err
	}

	un_marshal_err := json.Unmarshal(b, &tempMap)

	if un_marshal_err != nil {
		return nil, un_marshal_err
	}

	for k, v := range tempMap {
		if k != field && v.(string) != "" {
			mapResult[k] = v.(string)
		}
	}

	return mapResult, nil
}

func InSlice(in string, list []string) bool {
	for _, v := range list {
		if in == v {
			return true
		}
	}

	return false
}

func RandomMd5String(input string) string {
	ct := fmt.Sprint(time.Now().UTC().UnixMilli())
	input = ct + input
	hashedM5 := md5.Sum([]byte(input))

	return hex.EncodeToString(hashedM5[:])
}

func SliceStringToMapString(slice []string) map[string]string {
	resultMap := make(map[string]string, len(slice))

	for i := 0; i < len(slice); i += 2 {
		resultMap[slice[i]] = slice[i+1]
	}

	return resultMap
}

func LoadDotEnvToOsEnv(envfile string) error {
	data, err := os.ReadFile(envfile)

	if err != nil {
		return err
	}

	parsedData := parseEnvData(data)
	mapped_data := SliceStringToMapString(parsedData)

	for key, val := range mapped_data {
		os.Setenv(key, val)
	}

	return nil
}

func GenerateSecretKet(secretKeyEnvName string) ([]byte, error) {
	err := LoadDotEnvToOsEnv(".env")

	if err != nil {
		return nil, err
	}

	secret_key := os.Getenv(secretKeyEnvName)

	if secret_key == "" {
		return nil, fmt.Errorf("there is no 'SECRET_KEY' in .env file")
	}

	jwtKey := []byte(secret_key)
	return jwtKey, nil
}

func parseEnvData(data []byte) []string {
	var resultSlice []string

	stringData := string(data)
	splitByNewLine := strings.Split(stringData, "\n")

	for _, v := range splitByNewLine {
		v_slice := strings.Split(v, "=")
		resultSlice = append(resultSlice, v_slice...)
	}

	return resultSlice
}
